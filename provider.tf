########################################################
##  Project       :   Nasuni Kendra Integration
##  Organization  :   Nasuni Labs   
#########################################################

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.76.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

}
