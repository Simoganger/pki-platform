# Sentinel policy set enforced by HCP Terraform on every PKI workspace
# (attached by bootstrap/hcp-terraform). A hard-mandatory failure blocks the
# run; nobody can override it. Soft-mandatory can be overridden by an
# organization owner, which is logged (use for exceptions with a ticket).

policy "protect-certificate-authorities" {
  source            = "./protect-certificate-authorities.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "pca-key-algorithms" {
  source            = "./pca-key-algorithms.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "crl-required" {
  source            = "./crl-required.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "restrict-ram-sharing" {
  source            = "./restrict-ram-sharing.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "no-private-keys-in-state" {
  source            = "./no-private-keys-in-state.sentinel"
  enforcement_level = "hard-mandatory"
}

policy "require-pki-tags" {
  source            = "./require-pki-tags.sentinel"
  enforcement_level = "soft-mandatory"
}
