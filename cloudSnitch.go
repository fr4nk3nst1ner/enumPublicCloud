package main

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"enumcloud/pkg/banner"
	"enumcloud/pkg/cloud"
	"enumcloud/pkg/cloud/azure"
	"enumcloud/pkg/cloud/gcp"
)

func showHelp(showBanner bool, platform string) {
	// Display the colorized banner
	fmt.Println(banner.GetBanner(showBanner))
	
	// Show general help if no platform is specified
	if platform == "" {
		fmt.Println("\nCloud Resource Enumeration Tool")
		fmt.Println("=============================================")
		fmt.Println("\nUsage:")
		fmt.Println("  go run cloudSnitch.go -platform <PLATFORM> [OPTIONS] <RESOURCE_TYPE>")
		fmt.Println("\nRequired Flags:")
		fmt.Println("  -platform string    Cloud platform to enumerate (aws/gcp/azure)")
		fmt.Println("                      This flag is REQUIRED for all operations")
		fmt.Println("\nCommon Options:")
		fmt.Println("  -help               Show this help message")
		fmt.Println("  -examples           Show detailed examples for each platform")
		fmt.Println("  -nobanner           Silence the banner in all output")
		fmt.Println("  -output-format      Output format (text/json/csv)")
		fmt.Println("  -output-file        File to write output to")
		fmt.Println("\nPlatform-Specific Options:")
		fmt.Println("  AWS:")
		fmt.Println("    -profile          AWS profile name")
		fmt.Println("    -aws-account      AWS account ID")
		fmt.Println("    -accounts-file    File containing AWS account IDs")
		fmt.Println("\n  GCP:")
		fmt.Println("    -target-project   Target GCP project ID (required for GCP)")
		fmt.Println("\n  Azure:")
		fmt.Println("    -domain           Domain name for Azure tenant enumeration (required for Azure)")
		fmt.Println("    -subscription     Azure subscription ID")
		fmt.Println("\nResource Types:")
		fmt.Println("  Specify the resource type as the last argument (e.g., 'storage', 'compute', 'all')")
		fmt.Println("  Use -examples to see available resource types for each platform")
		fmt.Println("\nExamples:")
		fmt.Println("  # List all resources in a GCP project:")
		fmt.Println("  go run cloudSnitch.go -platform gcp -target-project PROJECT_ID all")
		fmt.Println("\n  # List public S3 buckets in AWS:")
		fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME s3")
		fmt.Println("\n  # Enumerate Azure tenant information based on domain:")
		fmt.Println("  go run cloudSnitch.go -platform azure -domain example.com")
		fmt.Println("\nFor more detailed examples, use: go run cloudSnitch.go -examples")
		return
	}
	
	// Show platform-specific help
	switch strings.ToLower(platform) {
	case "aws":
		showAWSHelp()
	case "gcp":
		showGCPHelp()
	case "azure":
		showAzureHelp()
	default:
		fmt.Printf("\nUnknown platform: %s\n", platform)
		fmt.Println("Supported platforms: aws, gcp, azure")
	}
	
	os.Exit(0)
}

func showAWSHelp() {
	fmt.Println("\nAWS Cloud Resource Enumeration")
	fmt.Println("==============================")
	fmt.Println("\nUsage:")
	fmt.Println("  go run cloudSnitch.go -platform aws [OPTIONS] <RESOURCE_TYPE>")
	fmt.Println("\nAWS-Specific Options:")
	fmt.Println("  -profile          AWS profile name to use")
	fmt.Println("  -aws-account      AWS account ID to enumerate")
	fmt.Println("  -accounts-file    File containing AWS account IDs (one per line)")
	fmt.Println("\nCommon Options:")
	fmt.Println("  -help             Show this help message")
	fmt.Println("  -examples         Show detailed examples")
	fmt.Println("  -nobanner         Silence the banner in all output")
	fmt.Println("  -output-format    Output format (text/json/csv)")
	fmt.Println("  -output-file      File to write output to")
	fmt.Println("\nSupported AWS Resource Types:")
	fmt.Println("  - ami        : Amazon Machine Images")
	fmt.Println("  - ebs        : EBS snapshots")
	fmt.Println("  - ecr        : Elastic Container Registry repositories")
	fmt.Println("  - s3         : S3 buckets")
	fmt.Println("  - ec2        : EC2 instances")
	fmt.Println("  - all        : All resource types")
	fmt.Println("\nExamples:")
	fmt.Println("  # List public AMIs in your account:")
	fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME ami")
	fmt.Println("\n  # List public EBS snapshots in specific account:")
	fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME -aws-account ACCOUNT_ID ebs")
	fmt.Println("\n  # List public ECR repositories from multiple accounts:")
	fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME -accounts-file accounts.txt ecr")
	fmt.Println("\n  # List all public resources in an account:")
	fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME -aws-account ACCOUNT_ID all")
}

func showGCPHelp() {
	fmt.Println("\nGCP Cloud Resource Enumeration")
	fmt.Println("=============================")
	fmt.Println("\nUsage:")
	fmt.Println("  go run cloudSnitch.go -platform gcp [OPTIONS] <RESOURCE_TYPE>")
	fmt.Println("\nGCP-Specific Options:")
	fmt.Println("  -target-project   Target GCP project ID (required)")
	fmt.Println("\nCommon Options:")
	fmt.Println("  -help             Show this help message")
	fmt.Println("  -examples         Show detailed examples")
	fmt.Println("  -nobanner         Silence the banner in all output")
	fmt.Println("  -output-format    Output format (text/json/csv)")
	fmt.Println("  -output-file      File to write output to")
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
	fmt.Println("\nExamples:")
	fmt.Println("  # Enumerate public storage buckets:")
	fmt.Println("  go run cloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID storage")
	fmt.Println("\n  # Enumerate public compute resources:")
	fmt.Println("  go run cloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID compute")
	fmt.Println("\n  # Enumerate public BigQuery datasets:")
	fmt.Println("  go run cloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID bigquery")
	fmt.Println("\n  # Enumerate all public resources:")
	fmt.Println("  go run cloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID all")
}

func showAzureHelp() {
	fmt.Println("\nAzure Cloud Resource Enumeration")
	fmt.Println("============================================")
	fmt.Println("\nUsage:")
	fmt.Println("  go run cloudSnitch.go -platform azure -domain DOMAIN [OPTIONS] <RESOURCE_TYPE>")
	fmt.Println("\nAzure-Specific Options:")
	fmt.Println("  -domain           Domain name for Azure tenant enumeration (REQUIRED)")
	fmt.Println("  -subscription     Azure subscription ID")
	fmt.Println("\nCommon Options:")
	fmt.Println("  -help             Show this help message")
	fmt.Println("  -examples         Show detailed examples")
	fmt.Println("  -nobanner         Silence the banner in all output")
	fmt.Println("  -output-format    Output format (text/json/csv)")
	fmt.Println("  -output-file      File to write output to")
	fmt.Println("\nPlanned Azure Resource Types:")
	fmt.Println("  - storage    : Storage accounts")
	fmt.Println("  - vm         : Virtual machines")
	fmt.Println("  - acr        : Container registries")
	fmt.Println("  - aks        : Kubernetes services")
	fmt.Println("  - all        : All resource types")
	fmt.Println("\nExamples:")
	fmt.Println("  # Enumerate Azure tenant information based on domain:")
	fmt.Println("  go run cloudSnitch.go -platform azure -domain example.com")
	fmt.Println("\n  # List public storage accounts:")
	fmt.Println("  go run cloudSnitch.go -platform azure -subscription SUB_ID storage")
	fmt.Println("\n  # List public VMs:")
	fmt.Println("  go run cloudSnitch.go -platform azure -subscription SUB_ID vm")
	fmt.Println("\n  # List all public resources:")
	fmt.Println("  go run cloudSnitch.go -platform azure -subscription SUB_ID all")
	fmt.Println("\nAzure Tenant Enumeration:")
	fmt.Println("  When using -domain flag, CloudSnitch will perform the following checks:")
	fmt.Println("  - Retrieve federation information")
	fmt.Println("  - Get tenant ID and name")
	fmt.Println("  - Discover associated domains")
	fmt.Println("  - Check for Microsoft 365 services (SharePoint, Exchange)")
	fmt.Println("  - Identify Azure services (App Services, Storage Accounts)")
	fmt.Println("  - Detect Microsoft Defender for Identity (MDI)")
	fmt.Println("  - Check for Teams and Skype for Business presence")
}

func showExamples(showBanner bool) {
	// Display the colorized banner if enabled
	fmt.Println(banner.GetBanner(showBanner))
	
	fmt.Println("Examples:")

	fmt.Println("\nAWS Examples:")
	fmt.Println("  # List public AMIs in your account:")
	fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME ami")
	fmt.Println("\n  # List public EBS snapshots in specific account:")
	fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME -aws-account ACCOUNT_ID ebs")
	fmt.Println("\n  # List public ECR repositories from multiple accounts:")
	fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME -accounts-file accounts.txt ecr")
	fmt.Println("\n  # List all public resources in an account:")
	fmt.Println("  go run cloudSnitch.go -platform aws -profile PROFILE_NAME -aws-account ACCOUNT_ID all")
	fmt.Println("\nSupported AWS Resource Types:")
	fmt.Println("  - ami        : Amazon Machine Images")
	fmt.Println("  - ebs        : EBS snapshots")
	fmt.Println("  - ecr        : Elastic Container Registry repositories")
	fmt.Println("  - s3         : S3 buckets")
	fmt.Println("  - ec2        : EC2 instances")
	fmt.Println("  - all        : All resource types")

	fmt.Println("\nGCP Examples:")
	fmt.Println("  # Enumerate public storage buckets:")
	fmt.Println("  go run cloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID storage")
	fmt.Println("\n  # Enumerate public compute resources:")
	fmt.Println("  go run cloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID compute")
	fmt.Println("\n  # Enumerate public BigQuery datasets:")
	fmt.Println("  go run cloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID bigquery")
	fmt.Println("\n  # Enumerate all public resources:")
	fmt.Println("  go run cloudSnitch.go -platform gcp -target-project TARGET_PROJECT_ID all")
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
	fmt.Println("  go run cloudSnitch.go -platform azure -subscription SUB_ID storage")
	fmt.Println("\n  # List public VMs:")
	fmt.Println("  go run cloudSnitch.go -platform azure -subscription SUB_ID vm")
	fmt.Println("\n  # List all public resources:")
	fmt.Println("  go run cloudSnitch.go -platform azure -subscription SUB_ID all")
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
	help := flagSet.Bool("help", false, "Show help message")
	noBanner := flagSet.Bool("nobanner", false, "Silence the banner in all output")
	domain := flagSet.String("domain", "", "Domain name for Azure tenant enumeration (required for Azure)")

	// Parse arguments
	if err := flagSet.Parse(os.Args[1:]); err != nil {
		cloud.ErrorLogger.Printf("Failed to parse arguments: %v", err)
		os.Exit(1)
	}

	// Show help if requested or if no arguments provided
	if *help || len(os.Args) == 1 {
		showHelp(!*noBanner, *platform)
	}

	// Show examples if requested
	if *examples {
		showExamples(!*noBanner)
	}

	// Get resource type from remaining arguments
	resourceType := ""
	if flagSet.NArg() > 0 {
		resourceType = flagSet.Arg(0)
	}

	// Validate platform
	if *platform == "" {
		cloud.ErrorLogger.Printf("Platform is required. Use -platform flag to specify aws, gcp, or azure")
		showHelp(!*noBanner, *platform)
		os.Exit(1)
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
	} else if config.Platform == "azure" {
		// For Azure, check if domain is provided
		if *domain == "" {
			cloud.ErrorLogger.Printf("Domain is required for Azure enumeration. Use -domain flag")
			os.Exit(1)
		}
		
		// Set domain in config
		config.Domain = *domain
	}

	// Create enumerator
	var enumerator cloud.Enumerator
	var err error

	switch config.Platform {
	case "gcp":
		enumerator, err = gcp.NewEnumerator(config)
	case "azure":
		enumerator, err = azure.NewEnumerator(config)
	default:
		cloud.ErrorLogger.Printf("Unsupported platform: %s", config.Platform)
		os.Exit(1)
	}

	if err != nil {
		cloud.ErrorLogger.Printf("Failed to create enumerator: %v", err)
		os.Exit(1)
	}

	// Display banner if enabled
	if !*noBanner {
		fmt.Println(banner.GetBanner(true))
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
		if resource.ID != "" {
			fmt.Printf("ID: %s\n", resource.ID)
		}
		if resource.Location != "" {
			fmt.Printf("Location: %s\n", resource.Location)
		}
		if resource.CreatedAt != "" {
			fmt.Printf("Created: %s\n", resource.CreatedAt)
		}
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