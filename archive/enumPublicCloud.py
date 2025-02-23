#!/usr/bin/env python3

import boto3
import json
import argparse
from google.cloud import storage, compute_v1, container_v1
from google.cloud import artifactregistry_v1
from azure.identity import DefaultAzureCredential
from azure.storage.blob import BlobServiceClient
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.containerservice import ContainerServiceClient
import logging
import sys
import csv
from pathlib import Path

# Set up logging
logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CloudEnumerator:
    def __init__(self, args):
        self.args = args
        self.results = {}
        self.setup_logging()

    def setup_logging(self):
        """Configure logging based on arguments"""
        log_level = getattr(logging, self.args.log_level)
        logger.setLevel(log_level)

        if self.args.log_file:
            file_handler = logging.FileHandler(self.args.log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
            logger.addHandler(file_handler)

    def init_aws(self):
        """Initialize AWS clients"""
        try:
            self.s3_client = boto3.client('s3')
            self.ec2_client = boto3.client('ec2')
            return True
        except Exception as e:
            logger.error(f"Failed to initialize AWS clients: {str(e)}")
            return False

    def init_gcp(self):
        """Initialize GCP clients"""
        try:
            self.storage_client = storage.Client()
            self.compute_client = compute_v1.InstancesClient()
            self.gke_client = container_v1.ClusterManagerClient()
            self.artifact_client = artifactregistry_v1.ArtifactRegistryClient()
            return True
        except Exception as e:
            logger.error(f"Failed to initialize GCP clients: {str(e)}")
            return False

    def init_azure(self):
        """Initialize Azure clients"""
        try:
            if not self.args.subscription_id:
                raise ValueError("Azure subscription ID is required")
            
            self.azure_credential = DefaultAzureCredential()
            self.resource_client = ResourceManagementClient(
                credential=self.azure_credential,
                subscription_id=self.args.subscription_id
            )
            self.compute_client = ComputeManagementClient(
                credential=self.azure_credential,
                subscription_id=self.args.subscription_id
            )
            self.network_client = NetworkManagementClient(
                credential=self.azure_credential,
                subscription_id=self.args.subscription_id
            )
            self.storage_client = StorageManagementClient(
                credential=self.azure_credential,
                subscription_id=self.args.subscription_id
            )
            self.container_registry_client = ContainerRegistryManagementClient(
                credential=self.azure_credential,
                subscription_id=self.args.subscription_id
            )
            self.aks_client = ContainerServiceClient(
                credential=self.azure_credential,
                subscription_id=self.args.subscription_id
            )
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Azure clients: {str(e)}")
            return False

    def enumerate_aws(self):
        """Enumerate AWS resources"""
        if not self.init_aws():
            return None

        try:
            results = {
                "s3_buckets": [],
                "ec2_instances": []
            }

            # List S3 buckets
            buckets = self.s3_client.list_buckets()
            for bucket in buckets['Buckets']:
                try:
                    location = self.s3_client.get_bucket_location(Bucket=bucket['Name'])
                    acl = self.s3_client.get_bucket_acl(Bucket=bucket['Name'])
                    results["s3_buckets"].append({
                        "name": bucket['Name'],
                        "creation_date": bucket['CreationDate'].isoformat(),
                        "location": location['LocationConstraint'],
                        "acl": acl
                    })
                except Exception as e:
                    logger.warning(f"Error accessing bucket {bucket['Name']}: {str(e)}")

            # List EC2 instances across all regions
            regions = [region['RegionName'] for region in self.ec2_client.describe_regions()['Regions']]
            for region in regions:
                ec2_client = boto3.client('ec2', region_name=region)
                instances = ec2_client.describe_instances()
                for reservation in instances['Reservations']:
                    for instance in reservation['Instances']:
                        results["ec2_instances"].append({
                            "id": instance['InstanceId'],
                            "type": instance['InstanceType'],
                            "state": instance['State']['Name'],
                            "region": region
                        })

            return results
        except Exception as e:
            logger.error(f"Error enumerating AWS resources: {str(e)}")
            return None

    def enumerate_gcp(self):
        """Enumerate GCP resources"""
        if not self.init_gcp():
            return None

        try:
            results = {
                "storage_buckets": [],
                "compute_instances": [],
                "gke_clusters": [],
                "artifacts": []
            }

            project_id = self.storage_client.project

            # List Storage buckets
            buckets = self.storage_client.list_buckets()
            for bucket in buckets:
                results["storage_buckets"].append({
                    "name": bucket.name,
                    "location": bucket.location,
                    "storage_class": bucket.storage_class
                })

            # List Compute instances
            request = compute_v1.ListInstancesRequest(project=project_id, zone='-')
            instances = self.compute_client.list(request=request)
            for instance in instances:
                results["compute_instances"].append({
                    "name": instance.name,
                    "machine_type": instance.machine_type,
                    "status": instance.status
                })

            # List GKE clusters
            parent = f"projects/{project_id}/locations/-"
            clusters = self.gke_client.list_clusters(parent=parent)
            for cluster in clusters.clusters:
                results["gke_clusters"].append({
                    "name": cluster.name,
                    "location": cluster.location,
                    "status": cluster.status
                })

            return results
        except Exception as e:
            logger.error(f"Error enumerating GCP resources: {str(e)}")
            return None

    def enumerate_azure(self):
        """Enumerate Azure resources"""
        if not self.init_azure():
            return None

        try:
            results = {
                "resource_groups": [],
                "virtual_machines": [],
                "storage_accounts": [],
                "container_registries": [],
                "aks_clusters": [],
                "network_interfaces": [],
                "public_ips": []
            }

            # List Resource Groups
            for group in self.resource_client.resource_groups.list():
                results["resource_groups"].append({
                    "name": group.name,
                    "location": group.location,
                    "tags": group.tags
                })
                
                # List VMs in resource group
                vms = self.compute_client.virtual_machines.list(group.name)
                for vm in vms:
                    results["virtual_machines"].append({
                        "name": vm.name,
                        "resource_group": group.name,
                        "location": vm.location,
                        "vm_size": vm.hardware_profile.vm_size
                    })

                # List Storage Accounts
                storage_accounts = self.storage_client.storage_accounts.list_by_resource_group(group.name)
                for account in storage_accounts:
                    results["storage_accounts"].append({
                        "name": account.name,
                        "resource_group": group.name,
                        "location": account.location,
                        "sku": account.sku.name
                    })

                # List Container Registries
                registries = self.container_registry_client.registries.list_by_resource_group(group.name)
                for registry in registries:
                    results["container_registries"].append({
                        "name": registry.name,
                        "resource_group": group.name,
                        "location": registry.location,
                        "login_server": registry.login_server
                    })

                # List AKS Clusters
                aks_clusters = self.aks_client.managed_clusters.list_by_resource_group(group.name)
                for cluster in aks_clusters:
                    results["aks_clusters"].append({
                        "name": cluster.name,
                        "resource_group": group.name,
                        "location": cluster.location,
                        "kubernetes_version": cluster.kubernetes_version
                    })

                # List Network Interfaces
                nics = self.network_client.network_interfaces.list(group.name)
                for nic in nics:
                    results["network_interfaces"].append({
                        "name": nic.name,
                        "resource_group": group.name,
                        "location": nic.location
                    })

                # List Public IPs
                public_ips = self.network_client.public_ip_addresses.list(group.name)
                for ip in public_ips:
                    results["public_ips"].append({
                        "name": ip.name,
                        "resource_group": group.name,
                        "location": ip.location,
                        "ip_address": ip.ip_address if ip.ip_address else "Not assigned"
                    })

            return results
        except Exception as e:
            logger.error(f"Error enumerating Azure resources: {str(e)}")
            return None

    def write_output(self, results):
        """Write results to output file in specified format"""
        if not results:
            logger.error("No results to write")
            return

        if self.args.output_file:
            output_path = Path(self.args.output_file)
            output_format = self.args.output_format

            try:
                if output_format == 'json':
                    with open(output_path, 'w') as f:
                        json.dump(results, f, indent=4, default=str)
                elif output_format == 'csv':
                    # Flatten the nested structure for CSV
                    flattened_data = self.flatten_results(results)
                    if flattened_data:
                        with open(output_path, 'w', newline='') as f:
                            writer = csv.DictWriter(f, fieldnames=flattened_data[0].keys())
                            writer.writeheader()
                            writer.writerows(flattened_data)
                else:  # text format
                    with open(output_path, 'w') as f:
                        self.write_text_output(f, results)

                logger.info(f"Results written to {output_path}")
            except Exception as e:
                logger.error(f"Error writing output: {str(e)}")
        else:
            # Print to stdout in text format
            self.write_text_output(sys.stdout, results)

    def flatten_results(self, results):
        """Flatten nested results structure for CSV output"""
        flattened = []
        for resource_type, items in results.items():
            for item in items:
                item['resource_type'] = resource_type
                flattened.append(item)
        return flattened

    def write_text_output(self, file, results):
        """Write results in text format"""
        for resource_type, items in results.items():
            file.write(f"\n{resource_type.upper()}:\n")
            file.write("=" * (len(resource_type) + 1) + "\n")
            for item in items:
                for key, value in item.items():
                    file.write(f"{key}: {value}\n")
                file.write("-" * 40 + "\n")

def parse_arguments():
    parser = argparse.ArgumentParser(description='Cloud Resource Enumerator for AWS, GCP, and Azure')
    subparsers = parser.add_subparsers(dest='platform', required=True)

    # AWS subparser
    aws_parser = subparsers.add_parser('aws', help='Enumerate AWS resources')
    aws_parser.add_argument('--profile', required=True, help='AWS CLI profile name')
    aws_parser.add_argument('--accounts-file', required=True, help='Path to file containing AWS account IDs')
    aws_parser.add_argument('--region', help='Specific region to check (default: all regions)')
    aws_parser.add_argument('--use-organization', action='store_true', help='Use AWS Organizations to discover accounts')
    aws_parser.add_argument('resource_type', choices=['ami', 'ebs', 'ecr'], 
                          help='Resource type to check')

    # GCP subparser
    gcp_parser = subparsers.add_parser('gcp', help='Enumerate GCP resources')
    gcp_parser.add_argument('--project-id', required=True, help='GCP Project ID to scan')
    gcp_parser.add_argument('--resource-types', nargs='+', 
                          choices=['storage', 'compute', 'gke', 'artifacts', 'all'],
                          default=['all'], help='Resource types to check')

    # Azure subparser
    azure_parser = subparsers.add_parser('azure', help='Enumerate Azure resources')
    azure_parser.add_argument('--subscription-id', required=True, help='Azure Subscription ID to scan')
    azure_parser.add_argument('--resource-types', nargs='+',
                           choices=['storage', 'compute', 'acr', 'aks', 'all'],
                           default=['all'], help='Resource types to check')

    # Common arguments for all platforms
    for p in [aws_parser, gcp_parser, azure_parser]:
        p.add_argument('--log-level', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                      default='INFO', help='Set the logging level')
        p.add_argument('--log-file', help='Optional file to write logs to')
        p.add_argument('--output-format', choices=['text', 'json', 'csv'],
                      default='text', help='Output format')
        p.add_argument('--output-file', help='File to write output to')

    return parser.parse_args()

def main():
    args = parse_arguments()
    
    try:
        enumerator = CloudEnumerator(args)
        
        # Initialize platform-specific settings
        if args.platform == 'aws':
            if not args.profile or not args.accounts_file:
                logger.error("AWS enumeration requires --profile and --accounts-file")
                sys.exit(1)
            results = enumerator.enumerate_aws()
        
        elif args.platform == 'gcp':
            if not args.project_id:
                logger.error("GCP enumeration requires --project-id")
                sys.exit(1)
            results = enumerator.enumerate_gcp()
        
        elif args.platform == 'azure':
            if not args.subscription_id:
                logger.error("Azure enumeration requires --subscription-id")
                sys.exit(1)
            results = enumerator.enumerate_azure()

        if results:
            enumerator.write_output(results)
        else:
            logger.error("Enumeration failed")
            sys.exit(1)

    except Exception as e:
        logger.error(f"Error in main execution: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
