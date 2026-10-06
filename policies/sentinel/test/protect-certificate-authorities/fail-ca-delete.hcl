mock "tfplan/v2" {
  module {
    source = "../../testdata/mock-tfplan-ca-delete.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}
