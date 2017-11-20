package aws

import (
	"fmt"
	"log"
	"regexp"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/gamelift"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func init() {
	resource.AddTestSweepers("aws_gamelift_build", &resource.Sweeper{
		Name: "aws_gamelift_build",
		F:    testSweepGameliftBuilds,
	})
}

func testSweepGameliftBuilds(region string) error {
	client, err := sharedClientForRegion(region)
	if err != nil {
		return fmt.Errorf("error getting client: %s", err)
	}
	conn := client.(*AWSClient).gameliftconn

	resp, err := conn.ListBuilds(&gamelift.ListBuildsInput{})
	if err != nil {
		return fmt.Errorf("Error listing Gamelift Builds: %s", err)
	}

	if len(resp.Builds) == 0 {
		log.Print("[DEBUG] No Gamelift Builds to sweep")
		return nil
	}

	log.Printf("[INFO] Found %d Gamelift Builds", len(resp.Builds))

	for _, build := range resp.Builds {
		if !strings.HasPrefix(*build.Name, "tf_acc_build_") {
			continue
		}

		log.Printf("[INFO] Deleting Gamelift Build %q", *build.BuildId)
		_, err := conn.DeleteBuild(&gamelift.DeleteBuildInput{
			BuildId: build.BuildId,
		})
		if err != nil {
			return fmt.Errorf("Error deleting Gamelift Build (%s): %s",
				*build.BuildId, err)
		}
	}

	return nil
}

func TestAccAWSGameliftBuild_basic(t *testing.T) {
	var conf gamelift.Build

	rString := acctest.RandString(8)

	buildName := fmt.Sprintf("tf_acc_build_%s", rString)
	uBuildName := fmt.Sprintf("tf_acc_build_updated_%s", rString)
	bucketName := fmt.Sprintf("tf-acc-bucket-gamelift-build-%s", rString)
	roleName := fmt.Sprintf("tf_acc_role_%s", rString)
	policyName := fmt.Sprintf("tf_acc_policy_%s", rString)

	roleArnRe := regexp.MustCompile(":role/" + roleName + "$")
	zipPath := "test-fixtures/gamelift-gomoku-build-sample.zip"

	resource.Test(t, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(t) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckAWSGameliftBuildDestroy,
		Steps: []resource.TestStep{
			{
				Config: testAccAWSGameliftBuildBasicConfig(buildName, bucketName, zipPath, roleName, policyName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSGameliftBuildExists("aws_gamelift_build.test", &conf),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "name", buildName),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "operating_system", "WINDOWS_2012"),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "storage_location.#", "1"),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "storage_location.0.bucket", bucketName),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "storage_location.0.key", "tf-acc-test-gl-build.zip"),
					resource.TestMatchResourceAttr("aws_gamelift_build.test", "storage_location.0.role_arn", roleArnRe),
				),
			},
			{
				Config: testAccAWSGameliftBuildBasicUpdateConfig(uBuildName, bucketName, zipPath, roleName, policyName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckAWSGameliftBuildExists("aws_gamelift_build.test", &conf),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "name", uBuildName),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "operating_system", "WINDOWS_2012"),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "storage_location.#", "1"),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "storage_location.0.bucket", bucketName),
					resource.TestCheckResourceAttr("aws_gamelift_build.test", "storage_location.0.key", "tf-acc-test-gl-build.zip"),
					resource.TestMatchResourceAttr("aws_gamelift_build.test", "storage_location.0.role_arn", roleArnRe),
				),
			},
		},
	})
}

func testAccCheckAWSGameliftBuildExists(n string, res *gamelift.Build) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[n]
		if !ok {
			return fmt.Errorf("Not found: %s", n)
		}

		if rs.Primary.ID == "" {
			return fmt.Errorf("No Gamelift Build ID is set")
		}

		conn := testAccProvider.Meta().(*AWSClient).gameliftconn

		req := &gamelift.DescribeBuildInput{
			BuildId: aws.String(rs.Primary.ID),
		}
		out, err := conn.DescribeBuild(req)
		if err != nil {
			return err
		}

		b := out.Build

		if *b.BuildId != rs.Primary.ID {
			return fmt.Errorf("Gamelift Build not found")
		}

		*res = *b

		return nil
	}
}

func testAccCheckAWSGameliftBuildDestroy(s *terraform.State) error {
	conn := testAccProvider.Meta().(*AWSClient).gameliftconn

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "aws_gamelift_build" {
			continue
		}

		req := gamelift.DescribeBuildInput{
			BuildId: aws.String(rs.Primary.ID),
		}
		out, err := conn.DescribeBuild(&req)
		if err == nil {
			if *out.Build.BuildId == rs.Primary.ID {
				return fmt.Errorf("Gamelift Build still exists")
			}
		}
		if isAWSErr(err, gamelift.ErrCodeNotFoundException, "") {
			return nil
		}

		return err
	}

	return nil
}

func testAccAWSGameliftBuildBasicConfig(buildName, bucketName, zipPath, roleName, policyName string) string {
	return fmt.Sprintf(`
resource "aws_gamelift_build" "test" {
  name = "%s"
  operating_system = "WINDOWS_2012"
  storage_location {
    bucket = "${aws_s3_bucket.test.bucket}"
    key = "${aws_s3_bucket_object.test.key}"
    role_arn = "${aws_iam_role.test.arn}"
  }
  depends_on = ["aws_iam_role_policy.test"]
}

resource "aws_s3_bucket" "test" {
  bucket = "%s"
}

resource "aws_s3_bucket_object" "test" {
  bucket = "${aws_s3_bucket.test.bucket}"
  key    = "tf-acc-test-gl-build.zip"
  source = "%s"
  etag   = "${md5(file("%s"))}"
}

resource "aws_iam_role" "test" {
  name = "%s"
  path = "/"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "gamelift.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "test" {
  name = "%s"
  role = "${aws_iam_role.test.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectMetadata"
      ],
      "Resource": "${aws_s3_bucket.test.arn}/*",
      "Effect": "Allow"
    }
  ]
}
POLICY
}
`, buildName, bucketName, zipPath, zipPath, roleName, policyName)
}

func testAccAWSGameliftBuildBasicUpdateConfig(buildName, bucketName, zipPath, roleName, policyName string) string {
	return fmt.Sprintf(`
resource "aws_gamelift_build" "test" {
  name = "%s"
  operating_system = "WINDOWS_2012"
  storage_location {
    bucket = "${aws_s3_bucket.test.bucket}"
    key = "${aws_s3_bucket_object.test.key}"
    role_arn = "${aws_iam_role.test.arn}"
  }
  depends_on = ["aws_iam_role_policy.test"]
}

resource "aws_s3_bucket" "test" {
  bucket = "%s"
}

resource "aws_s3_bucket_object" "test" {
  bucket = "${aws_s3_bucket.test.bucket}"
  key    = "tf-acc-test-gl-build.zip"
  source = "%s"
  etag   = "${md5(file("%s"))}"
}

resource "aws_iam_role" "test" {
  name = "%s"
  path = "/"
  assume_role_policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Effect": "Allow",
      "Sid": ""
    }
  ]
}
POLICY
}

resource "aws_iam_role_policy" "test" {
  name = "%s"
  role = "${aws_iam_role.test.id}"

  policy = <<POLICY
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "s3:GetObject",
        "s3:GetObjectVersion",
        "s3:GetObjectMetadata"
      ],
      "Resource": "${aws_s3_bucket.test.arn}/*",
      "Effect": "Allow"
    }
  ]
}
POLICY
}
`, buildName, bucketName, zipPath, zipPath, roleName, policyName)
}
