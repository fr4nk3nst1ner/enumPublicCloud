package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"enumcloud/pkg/cloud"
	"enumcloud/pkg/cloud/gcp"
)

func showExamples() {
	fmt.Println("Examples:")

	fmt.Println("\nAWS Examples:")
	fmt.Println("  # List public AMIs in your account:")
	fmt.Println("  go run enumPublicCloud.go -platform aws -profile PROFILE_NAME ami")
	fmt.Println("\n  # List public EBS snapshots in specific account:")
	fmt.Println("  go run enumPublicCloud.go -platform aws -profile PROFILE_NAME -aws-account ACCOUNT_ID ebs")
	fmt.Println("\n  # List public ECR repositories from multiple accounts:")
	fmt.Println("  go run enumPublicCloud.go -platform aws -profile PROFILE_NAME -accounts-file accounts.txt ecr")
	fmt.Println("\n  # List all public resources in an account:")
	fmt.Println("  go run enumPublicCloud.go -platform aws -profile PROFILE_NAME -aws-account ACCOUNT_ID all")
	fmt.Println("\nSupported AWS Resource Types:")
	fmt.Println("  - ami        : Amazon Machine Images")
	fmt.Println("  - ebs        : EBS snapshots")
	fmt.Println("  - ecr        : Elastic Container Registry repositories")
	fmt.Println("  - s3         : S3 buckets")
	fmt.Println("  - ec2        : EC2 instances")
	fmt.Println("  - all        : All resource types")

	fmt.Println("\nGCP Examples:")
	fmt.Println("  # Enumerate public storage buckets:")
	fmt.Println("  go run enumPublicCloud.go -platform gcp -target-project TARGET_PROJECT_ID storage")
	fmt.Println("\n  # Enumerate public compute resources:")
	fmt.Println("  go run enumPublicCloud.go -platform gcp -target-project TARGET_PROJECT_ID compute")
	fmt.Println("\n  # Enumerate public BigQuery datasets:")
	fmt.Println("  go run enumPublicCloud.go -platform gcp -target-project TARGET_PROJECT_ID bigquery")
	fmt.Println("\n  # Enumerate all public resources:")
	fmt.Println("  go run enumPublicCloud.go -platform gcp -target-project TARGET_PROJECT_ID all")
	fmt.Println("\nSupported GCP Resource Types:")
	fmt.Println("  - storage    : Cloud Storage buckets")
	fmt.Println("  - compute    : Compute Engine snapshots and images")
	fmt.Println("  - bigquery   : BigQuery datasets")
	fmt.Println("  - iam        : IAM policies")
	fmt.Println("  - run        : Cloud Run services")
	fmt.Println("  - functions  : Cloud Functions")
	fmt.Println("  - artifacts  : Artifact Registry repositories")
	fmt.Println("  - secrets    : Secret Manager secrets")
	fmt.Println("  - sql        : Cloud SQL instances")
	fmt.Println("  - firestore  : Firestore collections")
	fmt.Println("  - pubsub     : Pub/Sub topics")
	fmt.Println("  - vpc        : VPC firewall rules")
	fmt.Println("  - build      : Cloud Build artifacts")
	fmt.Println("  - gke        : GKE clusters")
	fmt.Println("  - all        : All resource types")

	fmt.Println("\nAzure Examples (Coming Soon):")
	fmt.Println("  # List public storage accounts:")
	fmt.Println("  go run enumPublicCloud.go -platform azure -subscription SUB_ID storage")
	fmt.Println("\n  # List public VMs:")
	fmt.Println("  go run enumPublicCloud.go -platform azure -subscription SUB_ID vm")
	fmt.Println("\n  # List all public resources:")
	fmt.Println("  go run enumPublicCloud.go -platform azure -subscription SUB_ID all")
	fmt.Println("\nPlanned Azure Resource Types:")
	fmt.Println("  - storage    : Storage accounts")
	fmt.Println("  - vm         : Virtual machines")
	fmt.Println("  - acr        : Container registries")
	fmt.Println("  - aks        : Kubernetes services")
	fmt.Println("  - all        : All resource types")

	fmt.Println("\nCommon Flags:")
	fmt.Println("  -platform        Cloud platform to enumerate (aws/gcp/azure)")
	fmt.Println("  -output-format   Output format (text/json/csv)")
	fmt.Println("  -output-file     File to write output to")
	fmt.Println("  -examples        Show this help message")

	os.Exit(0)
}

func getCurrentGcloudConfig() (string, string, error) {
	// Get current account
	accountCmd := exec.Command("gcloud", "config", "get-value", "account")
	accountOutput, err := accountCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to get current gcloud account: %v", err)
	}
	account := strings.TrimSpace(string(accountOutput))

	// Get current project
	projectCmd := exec.Command("gcloud", "config", "get-value", "project")
	projectOutput, err := projectCmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to get current gcloud project: %v", err)
	}
	project := strings.TrimSpace(string(projectOutput))

	return account, project, nil
}

func main() {
	// Initialize logger with default configuration
	cloud.InitLogger(cloud.LogConfig{
		Level: "INFO",
	})

	// Parse flags
	flagSet := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	platform := flagSet.String("platform", "", "Cloud platform to enumerate (aws/gcp)")
	targetProject := flagSet.String("target-project", "", "Target GCP project ID (required for GCP)")
	examples := flagSet.Bool("examples", false, "Show example usage")

	// Parse arguments
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		cloud.ErrorLogger.Printf("Failed to parse arguments: %v", err)
		os.Exit(1)
	}

	// Show examples if requested
	if *examples {
		showExamples()
	}

	// Get resource type from remaining arguments
	resourceType := ""
	if flagSet.NArg() > 0 {
		resourceType = flagSet.Arg(0)
	}

	// Create configuration
	config := cloud.Config{
		Platform:      *platform,
		ResourceTypes: []string{resourceType},
	}

	// For GCP, get current account and project, and set target project
	if config.Platform == "gcp" {
		_, project, err := getCurrentGcloudConfig()
		if err != nil {
			cloud.ErrorLogger.Printf("Failed to get gcloud config: %v", err)
			os.Exit(1)
		}

		// Set source project as current project
		config.SourceProject = project

		// Set target project from flag
		if *targetProject == "" {
			cloud.ErrorLogger.Printf("Target GCP project ID is required. Use -target-project flag")
			os.Exit(1)
		}
		config.TargetProject = *targetProject

		// Log enumeration configuration
		cloud.InfoLogger.Printf("Enumeration configuration:")
		cloud.InfoLogger.Printf("  Source (Current) Project: %s", config.SourceProject)
		cloud.InfoLogger.Printf("  Target Project: %s", config.TargetProject)
		if resourceType != "" {
			cloud.InfoLogger.Printf("  Resource Type: %s", resourceType)
		}
	}

	// Validate platform
	if config.Platform == "" {
		cloud.ErrorLogger.Printf("Platform is required. Use -platform flag")
		os.Exit(1)
	}

	// Create enumerator
	var enumerator cloud.Enumerator
	var err error

	switch config.Platform {
	case "gcp":
		enumerator, err = gcp.NewEnumerator(config)
	default:
		cloud.ErrorLogger.Printf("Unsupported platform: %s", config.Platform)
		os.Exit(1)
	}

	if err != nil {
		cloud.ErrorLogger.Printf("Failed to create enumerator: %v", err)
		os.Exit(1)
	}

	// Run enumeration
	results, err := enumerator.Enumerate()
	if err != nil {
		cloud.ErrorLogger.Printf("Failed to enumerate resources: %v", err)
		os.Exit(1)
	}

	// Print results
	fmt.Printf("Platform: %s\n", results.Platform)
	fmt.Printf("Total Resources: %d\n", len(results.Resources))
	for _, resource := range results.Resources {
		fmt.Printf("\nResource: %s\n", resource.Type)
		fmt.Printf("Name: %s\n", resource.Name)
		fmt.Printf("ID: %s\n", resource.ID)
		fmt.Printf("Location: %s\n", resource.Location)
		fmt.Printf("Created: %s\n", resource.CreatedAt)
		if len(resource.Tags) > 0 {
			fmt.Printf("Tags:\n")
			for key, value := range resource.Tags {
				fmt.Printf("  %s: %s\n", key, value)
			}
		}
		if len(resource.Properties) > 0 {
			fmt.Printf("Properties:\n")
			for key, value := range resource.Properties {
				fmt.Printf("  %s: %v\n", key, value)
			}
		}
	}
} 