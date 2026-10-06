terraform {
  required_version = ">= 1.9.0"

  required_providers {
    datadog = {
      source  = "DataDog/datadog"
      version = ">= 3.60, < 4.0"
    }
  }
}
