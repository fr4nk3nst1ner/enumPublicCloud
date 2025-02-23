package aws

import (
	"context"
	"fmt"
	"time"

	"enumcloud/pkg/cloud"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/aws"
)

type Enumerator struct {
	config cloud.Config
	ctx    context.Context
}

func NewEnumerator(config cloud.Config) (cloud.Enumerator, error) {
	return &Enumerator{
		config: config,
		ctx:    context.Background(),
	}, nil
}

func (e *Enumerator) Enumerate() (*cloud.Results, error) {
	results := &cloud.Results{
		Platform:  "aws",
		Resources: make([]cloud.Resource, 0),
	}

	// Load AWS configuration
	cfg, err := config.LoadDefaultConfig(e.ctx,
		config.WithSharedConfigProfile(e.config.Profile),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to load AWS config: %v", err)
	}

	// Initialize clients
	ec2Client := ec2.NewFromConfig(cfg)

	// Check resource types
	for _, resourceType := range e.config.ResourceTypes {
		switch resourceType {
		case "ami":
			if err := e.enumerateAMIs(ec2Client, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate AMIs: %v", err)
			}
		case "ebs":
			if err := e.enumerateEBSSnapshots(ec2Client, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate EBS snapshots: %v", err)
			}
		case "s3":
			s3Client := s3.NewFromConfig(cfg)
			if err := e.enumerateS3(s3Client, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate S3 buckets: %v", err)
			}
		case "ec2":
			if err := e.enumerateEC2(ec2Client, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate EC2 instances: %v", err)
			}
		case "ecr":
			ecrClient := ecr.NewFromConfig(cfg)
			if err := e.enumerateECR(ecrClient, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate ECR repositories: %v", err)
			}
		case "all":
			s3Client := s3.NewFromConfig(cfg)
			ecrClient := ecr.NewFromConfig(cfg)
			
			if err := e.enumerateAMIs(ec2Client, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate AMIs: %v", err)
			}
			if err := e.enumerateEBSSnapshots(ec2Client, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate EBS snapshots: %v", err)
			}
			if err := e.enumerateS3(s3Client, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate S3 buckets: %v", err)
			}
			if err := e.enumerateEC2(ec2Client, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate EC2 instances: %v", err)
			}
			if err := e.enumerateECR(ecrClient, results); err != nil {
				cloud.ErrorLogger.Printf("Failed to enumerate ECR repositories: %v", err)
			}
		}
	}

	return results, nil
}

func (e *Enumerator) enumerateAMIs(client *ec2.Client, results *cloud.Results) error {
	cloud.InfoLogger.Printf("Enumerating public AMIs owned by account %s using profile %s...", e.config.AWSAccount, e.config.Profile)

	// Get list of regions
	regionsOutput, err := client.DescribeRegions(e.ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return fmt.Errorf("failed to list regions: %v", err)
	}

	for _, region := range regionsOutput.Regions {
		// Create region-specific client
		cfg, err := config.LoadDefaultConfig(e.ctx,
			config.WithSharedConfigProfile(e.config.Profile),
			config.WithRegion(*region.RegionName),
		)
		if err != nil {
			cloud.ErrorLogger.Printf("Failed to load config for region %s: %v", *region.RegionName, err)
			continue
		}
		
		regionalClient := ec2.NewFromConfig(cfg)
		
		// Match AWS CLI: aws ec2 describe-images --owners <account> --filters "Name=is-public,Values=true"
		input := &ec2.DescribeImagesInput{
			Owners: []string{e.config.AWSAccount},
			Filters: []types.Filter{
				{
					Name:   aws.String("is-public"),
					Values: []string{"true"},
				},
			},
		}

		cloud.InfoLogger.Printf("Checking region %s for public AMIs owned by account %s", *region.RegionName, e.config.AWSAccount)
		output, err := regionalClient.DescribeImages(e.ctx, input)
		if err != nil {
			cloud.ErrorLogger.Printf("Failed to describe AMIs in region %s: %v", *region.RegionName, err)
			continue
		}

		cloud.InfoLogger.Printf("Found %d public AMIs in region %s", len(output.Images), *region.RegionName)
		for _, image := range output.Images {
			cloud.InfoLogger.Printf("Found public AMI: %s in region %s", *image.ImageId, *region.RegionName)

			tags := make(map[string]string)
			for _, tag := range image.Tags {
				tags[*tag.Key] = *tag.Value
			}

			creationDate, _ := time.Parse(time.RFC3339, *image.CreationDate)

			resource := cloud.Resource{
				Type:      "ami",
				Name:      *image.Name,
				ID:        *image.ImageId,
				Location:  *region.RegionName,
				CreatedAt: creationDate,
				Tags:      tags,
				Properties: map[string]interface{}{
					"description":        aws.ToString(image.Description),
					"platform":          string(image.Platform),
					"architecture":      string(image.Architecture),
					"root_device_type":  string(image.RootDeviceType),
					"virtualization":    string(image.VirtualizationType),
					"public":            true,
					"owner_id":          *image.OwnerId,
					"state":             string(image.State),
				},
			}

			results.Resources = append(results.Resources, resource)
		}
	}

	return nil
}

func (e *Enumerator) enumerateEBSSnapshots(client *ec2.Client, results *cloud.Results) error {
	cloud.InfoLogger.Println("Enumerating public EBS snapshots...")

	// Get list of regions
	regionsOutput, err := client.DescribeRegions(e.ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return err
	}

	for _, region := range regionsOutput.Regions {
		cloud.InfoLogger.Printf("Checking region %s for public snapshots...", *region.RegionName)
		
		// Create region-specific client
		cfg, err := config.LoadDefaultConfig(e.ctx,
			config.WithSharedConfigProfile(e.config.Profile),
			config.WithRegion(*region.RegionName),
		)
		if err != nil {
			cloud.ErrorLogger.Printf("Failed to load config for region %s: %v", *region.RegionName, err)
			continue
		}
		
		regionalClient := ec2.NewFromConfig(cfg)
		
		// First get all snapshots owned by the account
		input := &ec2.DescribeSnapshotsInput{
			OwnerIds: []string{e.config.AWSAccount},
		}

		paginator := ec2.NewDescribeSnapshotsPaginator(regionalClient, input)
		for paginator.HasMorePages() {
			output, err := paginator.NextPage(e.ctx)
			if err != nil {
				cloud.ErrorLogger.Printf("Failed to describe snapshots in region %s: %v", *region.RegionName, err)
				continue
			}

			for _, snapshot := range output.Snapshots {
				// For each snapshot, try to describe it as if we were another account
				otherAccountCfg, err := config.LoadDefaultConfig(e.ctx,
					config.WithSharedConfigProfile(e.config.Profile),
					config.WithRegion(*region.RegionName),
				)
				if err != nil {
					continue
				}

				otherClient := ec2.NewFromConfig(otherAccountCfg)
				describeInput := &ec2.DescribeSnapshotsInput{
					SnapshotIds: []string{*snapshot.SnapshotId},
				}

				// If we can describe the snapshot without being the owner, it's public
				_, err = otherClient.DescribeSnapshots(e.ctx, describeInput)
				if err == nil {
					cloud.InfoLogger.Printf("Found public snapshot: %s in region %s", *snapshot.SnapshotId, *region.RegionName)

					tags := make(map[string]string)
					for _, tag := range snapshot.Tags {
						tags[*tag.Key] = *tag.Value
					}

					resource := cloud.Resource{
						Type:      "ebs-snapshot",
						Name:      getSnapshotName(snapshot.Tags),
						ID:        *snapshot.SnapshotId,
						Location:  *region.RegionName,
						CreatedAt: *snapshot.StartTime,
						Tags:      tags,
						Properties: map[string]interface{}{
							"description":     aws.ToString(snapshot.Description),
							"volume_id":       aws.ToString(snapshot.VolumeId),
							"volume_size":     snapshot.VolumeSize,
							"encrypted":       snapshot.Encrypted,
							"state":           string(snapshot.State),
							"owner_id":        *snapshot.OwnerId,
							"progress":        aws.ToString(snapshot.Progress),
							"public":          true,
						},
					}

					results.Resources = append(results.Resources, resource)
				}
			}
		}
	}

	return nil
}

func (e *Enumerator) enumerateS3(client *s3.Client, results *cloud.Results) error {
	cloud.InfoLogger.Println("Enumerating S3 buckets...")
	
	output, err := client.ListBuckets(e.ctx, &s3.ListBucketsInput{})
	if err != nil {
		return err
	}

	for _, bucket := range output.Buckets {
		// Get bucket location
		locOutput, err := client.GetBucketLocation(e.ctx, &s3.GetBucketLocationInput{
			Bucket: bucket.Name,
		})
		location := "us-east-1" // default
		if err == nil && locOutput.LocationConstraint != "" {
			location = string(locOutput.LocationConstraint)
		}

		// Get bucket tags
		tags := make(map[string]string)
		tagOutput, err := client.GetBucketTagging(e.ctx, &s3.GetBucketTaggingInput{
			Bucket: bucket.Name,
		})
		if err == nil {
			for _, tag := range tagOutput.TagSet {
				tags[*tag.Key] = *tag.Value
			}
		}

		resource := cloud.Resource{
			Type:      "s3-bucket",
			Name:      *bucket.Name,
			ID:        *bucket.Name,
			Location:  location,
			CreatedAt: *bucket.CreationDate,
			Tags:      tags,
			Properties: map[string]interface{}{
				"creation_date": bucket.CreationDate.Format(time.RFC3339),
			},
		}

		results.Resources = append(results.Resources, resource)
	}

	return nil
}

func (e *Enumerator) enumerateEC2(client *ec2.Client, results *cloud.Results) error {
	cloud.InfoLogger.Println("Enumerating EC2 instances...")

	// Get list of regions
	regionsOutput, err := client.DescribeRegions(e.ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return err
	}

	for _, region := range regionsOutput.Regions {
		// Create region-specific client
		cfg, err := config.LoadDefaultConfig(e.ctx,
			config.WithSharedConfigProfile(e.config.Profile),
			config.WithRegion(*region.RegionName),
		)
		if err != nil {
			cloud.ErrorLogger.Printf("Failed to load config for region %s: %v", *region.RegionName, err)
			continue
		}
		
		regionalClient := ec2.NewFromConfig(cfg)
		
		input := &ec2.DescribeInstancesInput{}
		output, err := regionalClient.DescribeInstances(e.ctx, input)
		if err != nil {
			cloud.ErrorLogger.Printf("Failed to describe instances in region %s: %v", *region.RegionName, err)
			continue
		}

		for _, reservation := range output.Reservations {
			for _, instance := range reservation.Instances {
				tags := make(map[string]string)
				for _, tag := range instance.Tags {
					tags[*tag.Key] = *tag.Value
				}

				resource := cloud.Resource{
					Type:      "ec2-instance",
					Name:      getInstanceName(instance.Tags),
					ID:        *instance.InstanceId,
					Location:  *region.RegionName,
					CreatedAt: *instance.LaunchTime,
					Tags:      tags,
					Properties: map[string]interface{}{
						"instance_type": string(instance.InstanceType),
						"state":        string(instance.State.Name),
						"private_ip":   instance.PrivateIpAddress,
						"public_ip":    instance.PublicIpAddress,
					},
				}

				results.Resources = append(results.Resources, resource)
			}
		}
	}

	return nil
}

func (e *Enumerator) enumerateECR(client *ecr.Client, results *cloud.Results) error {
	cloud.InfoLogger.Println("Enumerating public ECR repositories and images...")

	// Create a new EC2 client to get regions
	cfg, err := config.LoadDefaultConfig(e.ctx,
		config.WithSharedConfigProfile(e.config.Profile),
	)
	if err != nil {
		return fmt.Errorf("failed to load AWS config: %v", err)
	}
	
	ec2Client := ec2.NewFromConfig(cfg)
	regionsOutput, err := ec2Client.DescribeRegions(e.ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return err
	}

	for _, region := range regionsOutput.Regions {
		// Create region-specific client
		cfg, err := config.LoadDefaultConfig(e.ctx,
			config.WithSharedConfigProfile(e.config.Profile),
			config.WithRegion(*region.RegionName),
		)
		if err != nil {
			cloud.ErrorLogger.Printf("Failed to load config for region %s: %v", *region.RegionName, err)
			continue
		}

		regionalClient := ecr.NewFromConfig(cfg)

		// List repositories
		input := &ecr.DescribeRepositoriesInput{}
		paginator := ecr.NewDescribeRepositoriesPaginator(regionalClient, input)

		for paginator.HasMorePages() {
			output, err := paginator.NextPage(e.ctx)
			if err != nil {
				cloud.ErrorLogger.Printf("Failed to describe repositories in region %s: %v", *region.RegionName, err)
				continue
			}

			for _, repo := range output.Repositories {
				// Check repository policy for public access
				policyInput := &ecr.GetRepositoryPolicyInput{
					RepositoryName: repo.RepositoryName,
				}
				
				policyOutput, err := regionalClient.GetRepositoryPolicy(e.ctx, policyInput)
				if err != nil {
					// Skip if no policy (means private)
					continue
				}

				// Get repository tags
				tags := make(map[string]string)
				tagOutput, err := regionalClient.ListTagsForResource(e.ctx, &ecr.ListTagsForResourceInput{
					ResourceArn: repo.RepositoryArn,
				})
				if err == nil {
					for _, tag := range tagOutput.Tags {
						tags[*tag.Key] = *tag.Value
					}
				}

				// List images in repository
				imageInput := &ecr.DescribeImagesInput{
					RepositoryName: repo.RepositoryName,
				}
				
				imagePaginator := ecr.NewDescribeImagesPaginator(regionalClient, imageInput)
				var images []map[string]interface{}

				for imagePaginator.HasMorePages() {
					imageOutput, err := imagePaginator.NextPage(e.ctx)
					if err != nil {
						cloud.ErrorLogger.Printf("Failed to describe images in repository %s: %v", *repo.RepositoryName, err)
						continue
					}

					for _, image := range imageOutput.ImageDetails {
						imageInfo := map[string]interface{}{
							"digest":        aws.ToString(image.ImageDigest),
							"pushed_at":     image.ImagePushedAt,
							"size":          image.ImageSizeInBytes,
							"scan_findings": image.ImageScanStatus,
						}

						if image.ImageTags != nil {
							imageInfo["tags"] = image.ImageTags
						}

						images = append(images, imageInfo)
					}
				}

				resource := cloud.Resource{
					Type:      "ecr-repository",
					Name:      *repo.RepositoryName,
					ID:        *repo.RepositoryArn,
					Location:  *region.RegionName,
					CreatedAt: *repo.CreatedAt,
					Tags:      tags,
					Properties: map[string]interface{}{
						"registry_id":      *repo.RegistryId,
						"repository_uri":   *repo.RepositoryUri,
						"policy":          aws.ToString(policyOutput.PolicyText),
						"scan_on_push":    repo.ImageScanningConfiguration.ScanOnPush,
						"encryption_type": string(repo.EncryptionConfiguration.EncryptionType),
						"images":         images,
					},
				}

				results.Resources = append(results.Resources, resource)
			}
		}
	}

	return nil
}

func getInstanceName(tags []types.Tag) string {
	for _, tag := range tags {
		if *tag.Key == "Name" {
			return *tag.Value
		}
	}
	return "unnamed"
}

func getSnapshotName(tags []types.Tag) string {
	for _, tag := range tags {
		if *tag.Key == "Name" {
			return *tag.Value
		}
	}
	return "unnamed"
} 