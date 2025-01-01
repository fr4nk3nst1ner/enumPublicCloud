# Cloud Resource Enumerator

Tool to help identify and audit public-facing resources across multiple cloud providers.

### Supported Resources

#### AWS
- Amazon Machine Images (AMIs)
- EBS Snapshots
- ECR Repositories

#### GCP
- Storage Buckets
- Compute Instances
- GKE Clusters
- Artifact Registry

#### Azure
- Storage Accounts
- Virtual Machines
- Container Registries
- AKS Clusters
- Network Interfaces
- Public IP Addresses

## Installation

1. Clone the repository:

```bash
git clone https://github.com/fr4nk3nst1ner/enumPublicCloud.git
cd cloud-resource-enumerator
```

2. Install required dependencies:

```bash
pip install -r requirements.txt
```

3. Configure cloud provider credentials:

### AWS Configuration
- Configure AWS credentials using `aws configure --profile <profile-name>`
- Create an accounts file containing AWS account IDs (one per line)

### GCP Configuration
- Set up application default credentials:

```bash
gcloud auth application-default login
```

### Azure Configuration
- Log in to Azure CLI:

```bash
az login
```

## Usage

The tool uses a command-line interface with subcommands for each cloud provider.

### General Syntax
```bash
python3 enumPublicCloud.py <platform> [options]
```

### Common Options (All Platforms)
- `--log-level`: Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--log-file`: Specify a file for logging output
- `--output-format`: Choose output format (text, json, csv)
- `--output-file`: Specify output file path

### AWS Examples

1. Enumerate public AMIs:

```bash
python3 enumPublicCloud.py aws ami --profile myprofile --accounts-file accounts.txt
```

2. Check public EBS snapshots in a specific region:

```bash
python3 enumPublicCloud.py aws ebs --profile myprofile --accounts-file accounts.txt --region us-east-1
```

3. List public ECR repositories:

```bash
python3 enumPublicCloud.py aws ecr --profile myprofile --accounts-file accounts.txt --output-format json
```

### GCP Examples

1. Enumerate all resource types:

```bash
python3 enumPublicCloud.py gcp --project-id my-project --resource-types all
```

2. Check only storage and compute resources:

```bash
python3 enumPublicCloud.py gcp --project-id my-project --resource-types storage compute --output-format csv
```

### Azure Examples

1. Enumerate all Azure resources:

```bash
python3 enumPublicCloud.py azure --subscription-id "your-sub-id" --resource-types all
```

2. Check only storage and container resources:

```bash
python3 enumPublicCloud.py azure --subscription-id "your-sub-id" --resource-types storage acr
```

## Use Cases

1. **Security Auditing**
   - Identify publicly accessible resources across cloud providers
   - Generate reports for compliance requirements
   - Regular security posture assessments

2. **Resource Management**
   - Track resource usage across multiple cloud platforms
   - Identify unused or misconfigured resources
   - Generate inventory reports

3. **Cost Optimization**
   - Identify potentially unnecessary public resources
   - Track resource distribution across regions
   - Monitor resource types and configurations

## Output Examples

### Text Format
```text
STORAGE_BUCKETS:
=================
name: example-bucket
location: us-east1
storage_class: STANDARD
----------------------------------------
```

### JSON Format
```json
{
  "storage_buckets": [
    {
      "name": "example-bucket",
      "location": "us-east1",
      "storage_class": "STANDARD"
    }
  ]
}
```

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for legitimate security auditing and resource management purposes only. Always ensure you have proper authorization before scanning cloud resources. 
