terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}
provider "aws" {
  region = "eu-west-1"
}
resource "aws_s3_bucket" "audit_bucket" {
  bucket = "toprakaydogmus-lab-audit-log-bucket"
}
