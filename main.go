package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strings"
	"fmt"

	"enumcloud/pkg/cloud"
	"enumcloud/pkg/cloud/aws"
	"enumcloud/pkg/cloud/gcp"
	"enumcloud/pkg/cloud/azure"
)

// getEnvOrDefault returns environment variable value or default if not set
func getEnvOrDefault(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

func showExamples(platform string) {
	switch strings.ToLower(platform) {
	case "aws":
		fmt.Println("\nAWS Examples (using environment variables):")
		fmt.Println("# Required environment variables:")
		fmt.Println("  export AWS_PROFILE=your-aws-profile")
		fmt.Println("  export AWS_ACCOUNT_ID=your-aws-account-id")
		fmt.Println("  export AWS_ACCOUNTS_FILE=path/to/accounts-file  # Optional, for multiple accounts")
		fmt.Println("\n# Current Account Examples (using your profile's account):")
		fmt.Println("  # List public AMIs in your account:")
		fmt.Println("  go run enumPublicCloud.go -platform aws ami")
		fmt.Println("\n  # List public EBS snapshots in your account:")
		fmt.Println("  go run enumPublicCloud.go -platform aws ebs")
		fmt.Println("\n  # List public ECR repositories in your account:")
		fmt.Println("  go run enumPublicCloud.go -platform aws ecr")
		fmt.Println("\n# Target Other Account Examples:")
		fmt.Println("  # List public AMIs from specific account:")
		fmt.Println("  go run enumPublicCloud.go -platform aws ami --aws-account $AWS_ACCOUNT_ID")
		fmt.Println("\n  # List public EBS snapshots from multiple accounts:")
		fmt.Println("  go run enumPublicCloud.go -platform aws ebs --accounts-file $AWS_ACCOUNTS_FILE")

	case "gcp":
		fmt.Println("\nGCP Examples:")
		fmt.Println("# Required environment variables:")
		fmt.Println("  export GCP_PROJECT_ID=your-gcp-project-id")
		fmt.Println("  export GCP_ACCOUNT=your-gcp-account@domain.com")
		fmt.Println("\n# Current Project Examples (using your authenticated account):")
		fmt.Println("  # List all resources in current project:")
		fmt.Println("  go run enumPublicCloud.go -platform gcp all")
		fmt.Println("\n  # List only Compute Engine instances:")
		fmt.Println("  go run enumPublicCloud.go -platform gcp compute")
		fmt.Println("\n# Target Other Project/Account Examples:")
		fmt.Println("  # List resources using specific account:")
		fmt.Println("  go run enumPublicCloud.go -platform gcp all -account $GCP_ACCOUNT")
		fmt.Println("\n  # List resources in specific project with specific account:")
		fmt.Println("  go run enumPublicCloud.go -platform gcp all -gcp-project-id $GCP_PROJECT_ID -account $GCP_ACCOUNT")

	case "azure":
		fmt.Println("\nAzure Examples:")
		fmt.Println("# Required environment variables:")
		fmt.Println("  export AZURE_SUBSCRIPTION_ID=your-subscription-id")
		fmt.Println("\n# Current Subscription Examples (using your authenticated subscription):")
		fmt.Println("  # List all resources in current subscription:")
		fmt.Println("  go run enumPublicCloud.go -platform azure all")
		fmt.Println("\n# Target Other Subscription Examples:")
		fmt.Println("  # List resources in specific subscription:")
		fmt.Println("  go run enumPublicCloud.go -platform azure all --subscription-id $AZURE_SUBSCRIPTION_ID")

	default:
		fmt.Println("Please specify a valid platform (aws, gcp, or azure) with -platform flag")
	}
}

func Main() {
	// Define command-line flags
	flag.Usage = func() {
		log.Printf("Usage: %s -platform <aws|gcp|azure> [resource-type] [options]\n", os.Args[0])
		log.Printf("\nResource Types:\n")
		log.Printf("  AWS: ami, ebs, s3, ec2, ecr\n")
		log.Printf("  GCP: compute, storage, gke, artifacts\n")
		log.Printf("  Azure: vm, storage, acr, aks\n")
		log.Printf("\nOptions:\n")
		flag.PrintDefaults()
		log.Printf("\nEnvironment Variables:\n")
		log.Printf("  AWS_PROFILE           AWS CLI profile name\n")
		log.Printf("  AWS_ACCOUNT_ID        AWS account ID\n")
		log.Printf("  GCP_PROJECT_ID        GCP project ID\n")
		log.Printf("  GCP_ACCOUNT           GCP account email\n")
		log.Printf("  AZURE_SUBSCRIPTION_ID Azure subscription ID\n")
	}

	// Define flags
	platform := flag.String("platform", "", "Cloud platform to enumerate (aws, gcp, azure)")
	examples := flag.Bool("examples", false, "Show example commands for the specified platform")
	profile := flag.String("profile", "", "AWS CLI profile name")
	accountsFile := flag.String("accounts-file", getEnvOrDefault("AWS_ACCOUNTS_FILE", ""), "Path to file containing AWS account IDs")
	awsAccount := flag.String("aws-account", getEnvOrDefault("AWS_ACCOUNT_ID", ""), "AWS account ID")
	gcpProjectID := flag.String("gcp-project-id", getEnvOrDefault("GCP_PROJECT_ID", ""), "GCP Project ID")
	account := flag.String("account", "", "Account email (for GCP) or account ID (for AWS)")
	azureSubscriptionID := flag.String("subscription-id", getEnvOrDefault("AZURE_SUBSCRIPTION_ID", ""), "Azure Subscription ID")
	logLevel := flag.String("log-level", "INFO", "Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)")
	logFile := flag.String("log-file", "", "Log file path")
	outputFormat := flag.String("output-format", "text", "Output format (text, json, csv)")
	outputFile := flag.String("output-file", "", "Output file path")

	flag.Parse()

	if *platform == "" {
		log.Fatal("Platform is required. Use -platform flag with aws, gcp, or azure")
	}

	// If examples flag is set, show examples and exit
	if *examples {
		showExamples(*platform)
		return
	}

	// Initialize logger early
	logConfig := cloud.LogConfig{
		Level:    *logLevel,
		FilePath: *logFile,
	}
	if err := cloud.InitLogger(logConfig); err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	// Get resource type from positional arguments
	resourceType := "all"
	if flag.NArg() > 0 {
		resourceType = flag.Arg(0)
	}

	// Process command line flags and environment variables
	// Command line flags take precedence over environment variables
	if *account != "" {
		switch strings.ToLower(*platform) {
		case "aws":
			*awsAccount = *account
		case "gcp":
			*gcpProjectID = *account
		}
	}

	// Handle AWS profile - command line flag takes precedence
	if *profile != "" {
		// Use profile directly from command line flag
		cloud.InfoLogger.Printf("Using AWS profile from command line: %s", *profile)
	} else if envProfile := os.Getenv("AWS_PROFILE"); envProfile != "" {
		// Fall back to environment variable
		*profile = envProfile
		cloud.InfoLogger.Printf("Using AWS profile from environment: %s", *profile)
	}

	// Validate required configuration based on platform
	switch strings.ToLower(*platform) {
	case "aws":
		if *profile == "" {
			log.Fatal("AWS profile is required. Set AWS_PROFILE environment variable or use -profile flag")
		}
		if *awsAccount == "" {
			log.Fatal("AWS account ID is required. Set AWS_ACCOUNT_ID environment variable or use -aws-account flag")
		}
	case "gcp":
		if *gcpProjectID == "" && os.Getenv("GCP_PROJECT_ID") == "" {
			log.Fatal("GCP project ID is required. Set GCP_PROJECT_ID environment variable or use -gcp-project-id flag")
		}
	case "azure":
		if *azureSubscriptionID == "" && os.Getenv("AZURE_SUBSCRIPTION_ID") == "" {
			log.Fatal("Azure subscription ID is required. Set AZURE_SUBSCRIPTION_ID environment variable or use -subscription-id flag")
		}
	}

	// Handle AWS accounts
	var awsAccounts []string
	if *accountsFile != "" {
		file, err := os.Open(*accountsFile)
		if err != nil {
			log.Fatalf("Failed to open accounts file: %v", err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			account := strings.TrimSpace(scanner.Text())
			if account != "" {
				awsAccounts = append(awsAccounts, account)
			}
		}

		if err := scanner.Err(); err != nil {
			log.Fatalf("Failed to read accounts file: %v", err)
		}
	} else if *account != "" && *platform == "aws" {
		awsAccounts = []string{*account}
	} else {
		awsAccounts = []string{*awsAccount}
	}

	// Process each account
	var allResults []*cloud.Results
	
	// Create base config
	config := cloud.Config{
		Platform:        *platform,
		Profile:         *profile,
		SourceProject:   *gcpProjectID,
		TargetProject:   *gcpProjectID,  // Initially set to same as source
		SubscriptionID:  *azureSubscriptionID,
		OutputFormat:    *outputFormat,
		OutputFile:      *outputFile,
		ResourceTypes:   []string{resourceType},
	}

	switch strings.ToLower(*platform) {
	case "aws":
		// Process each AWS account
		for _, account := range awsAccounts {
			config.AWSAccount = account
			enumerator, err := aws.NewEnumerator(config)
			if err != nil {
				log.Fatalf("Failed to create AWS enumerator: %v", err)
			}
			results, err := enumerator.Enumerate()
			if err != nil {
				log.Fatalf("AWS enumeration failed: %v", err)
			}
			allResults = append(allResults, results)
		}
	case "gcp":
		enumerator, err := gcp.NewEnumerator(config)
		if err != nil {
			log.Fatalf("Failed to create GCP enumerator: %v", err)
		}
		results, err := enumerator.Enumerate()
		if err != nil {
			log.Fatalf("GCP enumeration failed: %v", err)
		}
		allResults = append(allResults, results)
	case "azure":
		enumerator, err := azure.NewEnumerator(config)
		if err != nil {
			log.Fatalf("Failed to create Azure enumerator: %v", err)
		}
		results, err := enumerator.Enumerate()
		if err != nil {
			log.Fatalf("Azure enumeration failed: %v", err)
		}
		allResults = append(allResults, results)
	default:
		log.Fatalf("Unsupported platform: %s", *platform)
	}

	// Combine all results
	combinedResults := &cloud.Results{
		Platform:  allResults[0].Platform,
		Resources: make([]cloud.Resource, 0),
	}
	for _, result := range allResults {
		combinedResults.Resources = append(combinedResults.Resources, result.Resources...)
	}

	// Write combined results
	if err := cloud.WriteOutput(combinedResults, cloud.Config{
		OutputFormat: *outputFormat,
		OutputFile:  *outputFile,
	}); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}
} 