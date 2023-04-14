########################################################
##  Developed By  :   Pradeepta Kumar Sahu
##  Project       :   Nasuni Kendra Integration
##  Organization  :   Nasuni Labs   
#########################################################

variable "aws_profile" {
  type    = string
  default = "nasuni"
}

variable "region" {
  description = "Region for Kendra cluster"
  type        = string
  default     = "us-east-2"
}

variable "kendra_admin_secret" {
  default = "nasuni-labs-kendra-admin"
}

variable "github_organization" {
  default = "nasuni-labs"
}
