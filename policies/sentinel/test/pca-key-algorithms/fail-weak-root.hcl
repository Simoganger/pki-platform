mock "tfplan/v2" {
  module {
    source = "../../testdata/mock-tfplan-weak-root.sentinel"
  }
}

test {
  rules = {
    main = false
  }
}
