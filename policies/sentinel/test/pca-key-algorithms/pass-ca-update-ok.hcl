mock "tfplan/v2" {
  module {
    source = "../../testdata/mock-tfplan-ca-update-ok.sentinel"
  }
}

test {
  rules = {
    main = true
  }
}
