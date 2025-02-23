package azure

import (
	"context"
	"fmt"

	"enumcloud/pkg/cloud"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerregistry/armcontainerregistry"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armresources"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage"
)

type Enumerator struct {
	config cloud.Config
	ctx    context.Context
}

func NewEnumerator(config cloud.Config) (cloud.Enumerator, error) {
	if config.SubscriptionID == "" {
		return nil, fmt.Errorf("Azure subscription ID is required")
	}
	return &Enumerator{
		config: config,
		ctx:    context.Background(),
	}, nil
}

func (e *Enumerator) Enumerate() (*cloud.Results, error) {
	results := &cloud.Results{
		Platform:  "azure",
		Resources: make([]cloud.Resource, 0),
	}

	// Get Azure credentials
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %v", err)
	}

	// Initialize clients
	resourceClient, err := armresources.NewResourceGroupsClient(e.config.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource groups client: %v", err)
	}

	computeClient, err := armcompute.NewVirtualMachinesClient(e.config.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create compute client: %v", err)
	}

	storageClient, err := armstorage.NewAccountsClient(e.config.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create storage client: %v", err)
	}

	networkClient, err := armnetwork.NewInterfacesClient(e.config.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create network client: %v", err)
	}

	acrClient, err := armcontainerregistry.NewRegistriesClient(e.config.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create container registry client: %v", err)
	}

	aksClient, err := armcontainerservice.NewManagedClustersClient(e.config.SubscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create AKS client: %v", err)
	}

	// List resource groups
	resourceGroups, err := e.enumerateResourceGroups(resourceClient)
	if err != nil {
		cloud.ErrorLogger.Printf("Failed to enumerate resource groups: %v", err)
		return results, nil
	}

	// For each resource group, enumerate resources
	for _, group := range resourceGroups {
		// Enumerate VMs
		if err := e.enumerateVirtualMachines(computeClient, *group.Name, results); err != nil {
			cloud.ErrorLogger.Printf("Failed to enumerate VMs in resource group %s: %v", *group.Name, err)
		}

		// Enumerate Storage Accounts
		if err := e.enumerateStorageAccounts(storageClient, *group.Name, results); err != nil {
			cloud.ErrorLogger.Printf("Failed to enumerate storage accounts in resource group %s: %v", *group.Name, err)
		}

		// Enumerate Network Interfaces
		if err := e.enumerateNetworkInterfaces(networkClient, *group.Name, results); err != nil {
			cloud.ErrorLogger.Printf("Failed to enumerate network interfaces in resource group %s: %v", *group.Name, err)
		}

		// Enumerate Container Registries
		if err := e.enumerateContainerRegistries(acrClient, *group.Name, results); err != nil {
			cloud.ErrorLogger.Printf("Failed to enumerate container registries in resource group %s: %v", *group.Name, err)
		}

		// Enumerate AKS Clusters
		if err := e.enumerateAKSClusters(aksClient, *group.Name, results); err != nil {
			cloud.ErrorLogger.Printf("Failed to enumerate AKS clusters in resource group %s: %v", *group.Name, err)
		}
	}

	return results, nil
}

func (e *Enumerator) enumerateResourceGroups(client *armresources.ResourceGroupsClient) ([]*armresources.ResourceGroup, error) {
	pager := client.NewListPager(nil)
	var groups []*armresources.ResourceGroup

	for pager.More() {
		page, err := pager.NextPage(e.ctx)
		if err != nil {
			return nil, err
		}
		groups = append(groups, page.ResourceGroupListResult.Value...)
	}

	return groups, nil
}

func (e *Enumerator) enumerateVirtualMachines(client *armcompute.VirtualMachinesClient, resourceGroup string, results *cloud.Results) error {
	pager := client.NewListPager(resourceGroup, nil)

	for pager.More() {
		page, err := pager.NextPage(e.ctx)
		if err != nil {
			return err
		}

		for _, vm := range page.Value {
			tags := make(map[string]string)
			if vm.Tags != nil {
				for k, v := range vm.Tags {
					if v != nil {
						tags[k] = *v
					}
				}
			}

			resource := cloud.Resource{
				Type:     "virtual-machine",
				Name:     *vm.Name,
				ID:       *vm.ID,
				Location: *vm.Location,
				Tags:     tags,
				Properties: map[string]interface{}{
					"vm_size":        vm.Properties.HardwareProfile.VMSize,
					"os_type":        vm.Properties.StorageProfile.OSDisk.OSType,
					"admin_username": vm.Properties.OSProfile.AdminUsername,
				},
			}

			results.Resources = append(results.Resources, resource)
		}
	}

	return nil
}

func (e *Enumerator) enumerateStorageAccounts(client *armstorage.AccountsClient, resourceGroup string, results *cloud.Results) error {
	pager := client.NewListByResourceGroupPager(resourceGroup, nil)

	for pager.More() {
		page, err := pager.NextPage(e.ctx)
		if err != nil {
			return err
		}

		for _, account := range page.Value {
			tags := make(map[string]string)
			if account.Tags != nil {
				for k, v := range account.Tags {
					if v != nil {
						tags[k] = *v
					}
				}
			}

			resource := cloud.Resource{
				Type:     "storage-account",
				Name:     *account.Name,
				ID:       *account.ID,
				Location: *account.Location,
				Tags:     tags,
				Properties: map[string]interface{}{
					"sku_name":      string(*account.SKU.Name),
					"sku_tier":      string(*account.SKU.Tier),
					"access_tier":   string(*account.Properties.AccessTier),
					"https_only":    *account.Properties.EnableHTTPSTrafficOnly,
				},
			}

			results.Resources = append(results.Resources, resource)
		}
	}

	return nil
}

func (e *Enumerator) enumerateNetworkInterfaces(client *armnetwork.InterfacesClient, resourceGroup string, results *cloud.Results) error {
	pager := client.NewListPager(resourceGroup, nil)

	for pager.More() {
		page, err := pager.NextPage(e.ctx)
		if err != nil {
			return err
		}

		for _, nic := range page.Value {
			tags := make(map[string]string)
			if nic.Tags != nil {
				for k, v := range nic.Tags {
					if v != nil {
						tags[k] = *v
					}
				}
			}

			resource := cloud.Resource{
				Type:     "network-interface",
				Name:     *nic.Name,
				ID:       *nic.ID,
				Location: *nic.Location,
				Tags:     tags,
				Properties: map[string]interface{}{
					"enable_ip_forwarding": *nic.Properties.EnableIPForwarding,
					"ip_configurations":    len(nic.Properties.IPConfigurations),
				},
			}

			results.Resources = append(results.Resources, resource)
		}
	}

	return nil
}

func (e *Enumerator) enumerateContainerRegistries(client *armcontainerregistry.RegistriesClient, resourceGroup string, results *cloud.Results) error {
	pager := client.NewListByResourceGroupPager(resourceGroup, nil)

	for pager.More() {
		page, err := pager.NextPage(e.ctx)
		if err != nil {
			return err
		}

		for _, registry := range page.Value {
			tags := make(map[string]string)
			if registry.Tags != nil {
				for k, v := range registry.Tags {
					if v != nil {
						tags[k] = *v
					}
				}
			}

			resource := cloud.Resource{
				Type:     "container-registry",
				Name:     *registry.Name,
				ID:       *registry.ID,
				Location: *registry.Location,
				Tags:     tags,
				Properties: map[string]interface{}{
					"login_server":  *registry.Properties.LoginServer,
					"admin_enabled": *registry.Properties.AdminUserEnabled,
					"sku":          string(*registry.SKU.Name),
				},
			}

			results.Resources = append(results.Resources, resource)
		}
	}

	return nil
}

func (e *Enumerator) enumerateAKSClusters(client *armcontainerservice.ManagedClustersClient, resourceGroup string, results *cloud.Results) error {
	pager := client.NewListByResourceGroupPager(resourceGroup, nil)

	for pager.More() {
		page, err := pager.NextPage(e.ctx)
		if err != nil {
			return err
		}

		for _, cluster := range page.Value {
			tags := make(map[string]string)
			if cluster.Tags != nil {
				for k, v := range cluster.Tags {
					if v != nil {
						tags[k] = *v
					}
				}
			}

			resource := cloud.Resource{
				Type:     "aks-cluster",
				Name:     *cluster.Name,
				ID:       *cluster.ID,
				Location: *cluster.Location,
				Tags:     tags,
				Properties: map[string]interface{}{
					"kubernetes_version": *cluster.Properties.KubernetesVersion,
					"node_count":        len(cluster.Properties.AgentPoolProfiles),
					"fqdn":             cluster.Properties.Fqdn,
				},
			}

			results.Resources = append(results.Resources, resource)
		}
	}

	return nil
} 