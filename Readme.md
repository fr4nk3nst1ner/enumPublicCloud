# CloudSnitch

A tool for enumerating publicly accessible or cross-account shared cloud resources across AWS, GCP, and Azure cloud platforms.

## Features

- Multi-cloud resource enumeration:
  - AWS resources (S3 buckets, EC2 instances, ECR repositories, public AMIs, public EBS snapshots)
  - GCP resources (Storage buckets, Compute Engine resources, BigQuery datasets, and more)
  - Azure resources (coming soon)
- Identifies resources that are:
  - Publicly accessible
  - Shared across accounts/projects
  - Potentially misconfigured
- Detailed resource information including:
  - Resource type and name
  - Creation time and location
  - Access policies and permissions
  - Resource-specific properties
  - Tags and labels
- User-friendly error handling with clear messages
- Multiple output formats (text, JSON, CSV)

## Prerequisites

- Go 1.19 or later
- For AWS:
  - AWS CLI configured with credentials
  - AWS profile with necessary permissions
  - Target account ID(s) for cross-account enumeration
- For GCP:
  - `gcloud` CLI tool installed and configured
  - Active gcloud configuration with necessary permissions
  - Target project ID for cross-project enumeration
- For Azure (coming soon):
  - Azure CLI configured with credentials
  - Subscription ID with necessary permissions

## Installation

```bash
git clone https://github.com/fr4nk3nst1ner/CloudSnitch.git
cd CloudSnitch
go build
```

## Usage

Basic syntax:
```bash
go run CloudSnitch.go -platform PLATFORM [flags] RESOURCE_TYPE
```

Common flags:
```
-platform        Cloud platform to enumerate (aws/gcp/azure)
-output-format   Output format (text/json/csv)
-output-file     File to write output to
-examples        Show example usage
```

To see example usage and supported resource types:
```bash
go run CloudSnitch.go -examples
```

### AWS Usage

AWS-specific flags:
```
-profile         AWS profile to use
-aws-account     Target AWS account ID
-accounts-file   File containing list of AWS account IDs
```

Example commands:
```bash
# List public AMIs in your account
go run CloudSnitch.go -platform aws -profile myprofile ami

# List public EBS snapshots in specific account
go run CloudSnitch.go -platform aws -profile myprofile -aws-account 123456789012 ebs

# List public ECR repositories from multiple accounts
go run CloudSnitch.go -platform aws -profile myprofile -accounts-file accounts.txt ecr

# List all public resources in an account
go run CloudSnitch.go -platform aws -profile myprofile -aws-account 123456789012 all
```

Supported AWS resource types:
- `ami`: Amazon Machine Images
- `ebs`: EBS snapshots
- `ecr`: Elastic Container Registry repositories
- `s3`: S3 buckets
- `ec2`: EC2 instances
- `all`: All resource types

### GCP Usage

GCP-specific flags:
```
-target-project   Target GCP project ID
```

Example commands:
```bash
# Enumerate public storage buckets
go run CloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID storage

# Enumerate public compute resources
go run CloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID compute

# Enumerate public BigQuery datasets
go run CloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID bigquery

# Enumerate all public resources
go run CloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID all
```

Supported GCP resource types:
- `storage`: Cloud Storage buckets
- `compute`: Compute Engine snapshots and images
- `bigquery`: BigQuery datasets
- `iam`: IAM policies
- `run`: Cloud Run services
- `functions`: Cloud Functions
- `artifacts`: Artifact Registry repositories
- `secrets`: Secret Manager secrets
- `sql`: Cloud SQL instances
- `firestore`: Firestore collections
- `pubsub`: Pub/Sub topics
- `vpc`: VPC firewall rules
- `build`: Cloud Build artifacts
- `gke`: GKE clusters
- `all`: All resource types

### Azure Usage (Coming Soon)

Azure-specific flags:
```
-subscription    Azure subscription ID
```

Example commands (preview):
```bash
# List public storage accounts
go run CloudSnitch.go -platform azure -subscription SUB_ID storage

# List public VMs
go run CloudSnitch.go -platform azure -subscription SUB_ID vm

# List all public resources
go run CloudSnitch.go -platform azure -subscription SUB_ID all
```

Planned Azure resource types:
- `storage`: Storage accounts
- `vm`: Virtual machines
- `acr`: Container registries
- `aks`: Kubernetes services
- `all`: All resource types

## Output Formats

### Text (default)
```
Platform: aws
Total Resources: 1

Type: s3-bucket
Name: my-public-bucket
ID: my-public-bucket
Location: us-east-1
Created: 2024-02-22T10:00:00Z
Properties:
  public_access: true
  versioning_enabled: true
Tags:
  Environment: Production
----------------------------------------
```

### JSON
```json
{
  "platform": "aws",
  "resources": [
    {
      "type": "s3-bucket",
      "name": "my-public-bucket",
      "id": "my-public-bucket",
      "location": "us-east-1",
      "created_at": "2024-02-22T10:00:00Z",
      "properties": {
        "public_access": true,
        "versioning_enabled": true
      },
      "tags": {
        "Environment": "Production"
      }
    }
  ]
}
```

### CSV
```csv
Type,Name,ID,Location,Properties,Tags,CreatedAt
s3-bucket,my-public-bucket,my-public-bucket,us-east-1,"{""public_access"":true}","{""Environment"":""Production""}","2024-02-22T10:00:00Z"
```

## Error Handling

The tool provides clear error messages for common issues:

1. API/Service Errors:
```
Skipped APIs (not enabled):
- Compute Engine API is not enabled. Visit the Google Cloud Console to enable it.
```

2. Permission Errors:
```
Skipped Resources (insufficient permissions):
- Insufficient permissions to access Cloud Storage. Ensure necessary IAM roles.
```

3. Configuration Errors:
```
Error: AWS credentials not found. Configure AWS CLI or provide credentials.
Error: Target project ID required. Use -target-project flag.
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for legitimate security auditing and resource management purposes only. Always ensure you have proper authorization before scanning cloud resources. 
