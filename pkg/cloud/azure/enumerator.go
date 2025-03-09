package azure

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"enumcloud/pkg/cloud"
)

// Enumerator implements the cloud.Enumerator interface for Azure
type Enumerator struct {
	config cloud.Config
	domain string
}

// NewEnumerator creates a new Azure enumerator
func NewEnumerator(config cloud.Config) (*Enumerator, error) {
	// Validate domain is provided
	if config.Domain == "" {
		return nil, fmt.Errorf("domain is required for Azure enumeration")
	}

	return &Enumerator{
		config: config,
		domain: config.Domain,
	}, nil
}

// Enumerate performs the Azure tenant enumeration
func (e *Enumerator) Enumerate() (*cloud.EnumerationResults, error) {
	results := &cloud.EnumerationResults{
		Platform:  "azure",
		Resources: []cloud.Resource{},
	}

	// Step 1: Get federation information
	cloud.InfoLogger.Printf("Retrieving federation information...")
	fedInfo, err := e.getFederationInfo()
	if err != nil {
		cloud.ErrorLogger.Printf("Failed to get federation information: %v", err)
	} else {
		// Add federation info as a resource
		resource := cloud.Resource{
			Type: "federation_info",
			Name: "Federation Information",
			Properties: map[string]interface{}{
				"namespace_type":       fedInfo.NameSpaceType,
				"federation_brand_name": fedInfo.FederationBrandName,
				"cloud_instance":       fedInfo.CloudInstanceName,
				"domain_type":          fedInfo.DomainType,
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	// Step 2: Get tenant ID
	cloud.InfoLogger.Printf("Retrieving tenant ID...")
	tenantID, err := e.getTenantID()
	if err != nil {
		cloud.ErrorLogger.Printf("Failed to get tenant ID: %v", err)
	} else if tenantID != "" {
		// Add tenant ID as a resource
		resource := cloud.Resource{
			Type: "tenant",
			ID:   tenantID,
			Name: "Tenant ID",
		}
		results.Resources = append(results.Resources, resource)
	}

	// Step 3: Get tenant name and domains
	cloud.InfoLogger.Printf("Retrieving tenant domains...")
	domains, tenant, err := e.getTenantDomains()
	if err != nil {
		cloud.ErrorLogger.Printf("Failed to get tenant domains: %v", err)
	} else {
		// Add tenant name as a resource
		if tenant != "" {
			resource := cloud.Resource{
				Type: "tenant",
				Name: tenant,
				Properties: map[string]interface{}{
					"tenant_name": tenant,
				},
			}
			results.Resources = append(results.Resources, resource)
		}

		// Add domains as resources
		for _, domain := range domains {
			resource := cloud.Resource{
				Type: "domain",
				Name: domain,
			}
			results.Resources = append(results.Resources, resource)
		}
	}

	// Step 4: Check for Microsoft 365 services
	cloud.InfoLogger.Printf("Checking for Microsoft 365 services...")

	// Check SharePoint
	sharePointExists := e.checkSharePoint()
	if sharePointExists {
		resource := cloud.Resource{
			Type: "m365_service",
			Name: "SharePoint",
			Properties: map[string]interface{}{
				"status": "detected",
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	// Check MX records
	mxRecords, err := e.getMXRecords()
	if err == nil && len(mxRecords) > 0 {
		resource := cloud.Resource{
			Type: "m365_service",
			Name: "Exchange Online",
			Properties: map[string]interface{}{
				"mx_records": mxRecords,
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	// Check TXT records
	txtRecords, err := e.getTXTRecords()
	if err == nil && len(txtRecords) > 0 {
		resource := cloud.Resource{
			Type: "dns_records",
			Name: "TXT Records",
			Properties: map[string]interface{}{
				"txt_records": txtRecords,
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	// Check Autodiscover
	autodiscoverIP, err := e.getAutodiscoverEndpoint()
	if err == nil && autodiscoverIP != "" {
		resource := cloud.Resource{
			Type: "m365_service",
			Name: "Autodiscover",
			Properties: map[string]interface{}{
				"ip_address": autodiscoverIP,
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	// Step 5: Check for Azure services
	cloud.InfoLogger.Printf("Checking for Azure services...")

	// Check App Services
	appServices := e.checkAppServices()
	for url, status := range appServices {
		resource := cloud.Resource{
			Type: "app_service",
			Name: url,
			Properties: map[string]interface{}{
				"status": status,
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	// Check Storage Accounts
	storageAccounts := e.checkStorageAccounts()
	for _, storage := range storageAccounts {
		resource := cloud.Resource{
			Type: "storage_account",
			Name: storage.URL,
			Properties: map[string]interface{}{
				"status": storage.Status,
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	// Step 6: Check for Microsoft Defender for Identity (MDI)
	cloud.InfoLogger.Printf("Checking for Microsoft Defender for Identity (MDI)...")
	mdiDetected := e.checkMDI(tenant)
	if mdiDetected {
		resource := cloud.Resource{
			Type: "security_service",
			Name: "Microsoft Defender for Identity",
			Properties: map[string]interface{}{
				"status": "detected",
				"implications": []string{
					"MDI monitors AD authentication patterns and will detect suspicious Kerberos activity",
					"Lateral movement techniques like remote execution and NTLM relay attacks are monitored",
					"Consider AMSI bypass for post-exploitation tools and use of legitimate admin tools",
				},
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	// Step 7: Check for Teams and Skype
	cloud.InfoLogger.Printf("Checking for communication services...")
	teamsExists, skypeExists := e.checkTeamsPresence()
	if teamsExists {
		resource := cloud.Resource{
			Type: "m365_service",
			Name: "Microsoft Teams",
			Properties: map[string]interface{}{
				"status": "detected",
			},
		}
		results.Resources = append(results.Resources, resource)
	}
	if skypeExists {
		resource := cloud.Resource{
			Type: "m365_service",
			Name: "Skype for Business",
			Properties: map[string]interface{}{
				"status": "detected",
			},
		}
		results.Resources = append(results.Resources, resource)
	}

	cloud.InfoLogger.Printf("Azure tenant enumeration completed")
	return results, nil
}

// Federation info structure
type FederationInfo struct {
	NameSpaceType      string `json:"NameSpaceType"`
	FederationBrandName string `json:"FederationBrandName"`
	CloudInstanceName  string `json:"CloudInstanceName"`
	DomainType         string `json:"DomainType"`
}

// Storage account structure
type StorageAccount struct {
	URL    string
	Status string
}

// Get federation information for the domain
func (e *Enumerator) getFederationInfo() (*FederationInfo, error) {
	url := fmt.Sprintf("https://login.microsoftonline.com/getuserrealm.srf?login=user@%s&json=1", e.domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var fedInfo FederationInfo
	err = json.Unmarshal(body, &fedInfo)
	if err != nil {
		return nil, err
	}
	
	return &fedInfo, nil
}

// Get tenant ID from OpenID configuration
func (e *Enumerator) getTenantID() (string, error) {
	url := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", e.domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	
	var data map[string]interface{}
	err = json.Unmarshal(body, &data)
	if err != nil {
		return "", err
	}
	
	// Extract tenant ID from token endpoint
	if tokenEndpoint, ok := data["token_endpoint"].(string); ok {
		parts := strings.Split(tokenEndpoint, "/")
		if len(parts) > 3 {
			tenantID := parts[3]
			if tenantID != "v2.0" {
				return tenantID, nil
			}
		}
	}
	
	return "", nil
}

// Get tenant domains and name
func (e *Enumerator) getTenantDomains() ([]string, string, error) {
	// Create SOAP request body
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
	<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" 
		xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" 
		xmlns:a="http://www.w3.org/2005/08/addressing" 
		xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
		xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
		<soap:Header>
			<a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
			<a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
			<a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
			<a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
			<a:ReplyTo>
			<a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
			</a:ReplyTo>
		</soap:Header>
		<soap:Body>
			<GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
			<Request>
				<Domain>%s</Domain>
			</Request>
			</GetFederationInformationRequestMessage>
		</soap:Body>
	</soap:Envelope>`, e.domain)
	
	// Create HTTP request
	url := "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("User-Agent", "AutodiscoverClient")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	
	// Parse XML response
	domains := []string{}
	tenant := ""
	
	// Use regex to extract domains from XML
	domainRegex := regexp.MustCompile(`<Domain[^>]*>(.*?)</Domain>`)
	matches := domainRegex.FindAllStringSubmatch(string(respBody), -1)
	
	for _, match := range matches {
		if len(match) > 1 {
			domains = append(domains, match[1])
			// Extract tenant name from onmicrosoft.com domain
			if strings.Contains(match[1], "onmicrosoft.com") {
				parts := strings.Split(match[1], ".")
				if len(parts) > 0 {
					tenant = parts[0]
				}
			}
		}
	}
	
	return domains, tenant, nil
}

// Check if SharePoint exists
func (e *Enumerator) checkSharePoint() bool {
	domainPrefix := strings.Split(e.domain, ".")[0]
	url := fmt.Sprintf("https://%s.sharepoint.com", domainPrefix)
	
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	
	// If we get a 200 OK or 401/403 (auth required), SharePoint exists
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden
}

// Get MX records for the domain
func (e *Enumerator) getMXRecords() ([]string, error) {
	mxRecords := []string{}
	
	mx, err := net.LookupMX(e.domain)
	if err != nil {
		return mxRecords, err
	}
	
	for _, record := range mx {
		mxRecords = append(mxRecords, record.Host)
	}
	
	return mxRecords, nil
}

// Get TXT records for the domain
func (e *Enumerator) getTXTRecords() ([]string, error) {
	txtRecords := []string{}
	
	txt, err := net.LookupTXT(e.domain)
	if err != nil {
		return txtRecords, err
	}
	
	return txt, nil
}

// Get Autodiscover endpoint
func (e *Enumerator) getAutodiscoverEndpoint() (string, error) {
	autodiscoverDomain := fmt.Sprintf("autodiscover.%s", e.domain)
	
	ips, err := net.LookupIP(autodiscoverDomain)
	if err != nil {
		return "", err
	}
	
	if len(ips) > 0 {
		return ips[0].String(), nil
	}
	
	return "", nil
}

// Check for Azure App Services
func (e *Enumerator) checkAppServices() map[string]string {
	results := make(map[string]string)
	
	// Only check tenant-specific app service
	tenantBase := strings.Split(e.domain, ".")[0]
	appServiceURL := fmt.Sprintf("https://%s.azurewebsites.net", tenantBase)
	
	req, err := http.NewRequest("GET", appServiceURL, nil)
	if err != nil {
		results[appServiceURL] = "not_found"
		return results
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		results[appServiceURL] = "not_found"
		return results
	}
	defer resp.Body.Close()
	
	if resp.StatusCode == http.StatusOK {
		results[appServiceURL] = "accessible"
	} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		results[appServiceURL] = "auth_required"
	} else {
		results[appServiceURL] = "not_found"
	}
	
	return results
}

// Check for Azure Storage Accounts
func (e *Enumerator) checkStorageAccounts() []StorageAccount {
	results := []StorageAccount{}
	domainPrefix := strings.Split(e.domain, ".")[0]
	
	commonPrefixes := []string{"storage", "blob", "data", domainPrefix}
	
	for _, prefix := range commonPrefixes {
		urls := []string{
			fmt.Sprintf("https://%s.blob.core.windows.net", prefix),
			fmt.Sprintf("https://%s%s.blob.core.windows.net", prefix, domainPrefix),
			fmt.Sprintf("https://%s%s.blob.core.windows.net", domainPrefix, prefix),
		}
		
		for _, url := range urls {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				continue
			}
			req.Header.Set("User-Agent", "Mozilla/5.0")
			
			client := &http.Client{
				Timeout: 5 * time.Second,
			}
			resp, err := client.Do(req)
			if err != nil {
				continue
			}
			defer resp.Body.Close()
			
			if resp.StatusCode == http.StatusOK {
				results = append(results, StorageAccount{URL: url, Status: "accessible"})
			} else if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
				results = append(results, StorageAccount{URL: url, Status: "auth_required"})
			}
		}
	}
	
	return results
}

// Check for Microsoft Defender for Identity (MDI)
func (e *Enumerator) checkMDI(tenant string) bool {
	if tenant == "" {
		return false
	}
	
	mdiDomain := fmt.Sprintf("%s.atp.azure.com", tenant)
	
	_, err := net.LookupIP(mdiDomain)
	return err == nil
}

// Check for Teams and Skype presence
func (e *Enumerator) checkTeamsPresence() (bool, bool) {
	teamsExists := false
	skypeExists := false
	
	// Check Teams
	lyncdiscover := fmt.Sprintf("lyncdiscover.%s", e.domain)
	_, err := net.LookupCNAME(lyncdiscover)
	if err == nil {
		teamsExists = true
	}
	
	// Check Skype for Business
	sip := fmt.Sprintf("sip.%s", e.domain)
	_, err = net.LookupCNAME(sip)
	if err == nil {
		skypeExists = true
	}
	
	return teamsExists, skypeExists
} 