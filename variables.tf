########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni Kendra Integration
##  Organization  :   Nasuni Labs   
#########################################################

variable "aws_profile" {
  type    = string
  default = "nasuni"
}

variable "user_secret" {
  type    = string
  default = ""
}

variable "region" {
  description = "Region for Kendra cluster"
  type        = string
  default     = "us-east-2"
}

variable "aws_access_key" {
  default = ""
}
variable "aws_secret_key" {
  default = ""
}


################### Lambda PRovisioning Specific Variables ###################

variable "nac_destination_bucket" {
  default     = ""
  description = "S3 bucket where NAC will be updating the files/data"
}
variable "runtime" {
  default = "python3.9"
}
variable "admin_secret" {
  default = "admin_secret"
}
variable "internal_secret" {
  default = "nasuni-labs-internal-kendra"
}
variable "volume_name" {
  default = ""
}
variable "external_share_url" {
  default = ""
}


variable "github_organization" {
  default = "nasuni-labs"
}
