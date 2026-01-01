package types

// EffectiveDatasetVersion resolves the effective dataset version for a dataset reference within a check,
// per newspec.md section 4.1.
func EffectiveDatasetVersion(dataset string, dataContracts []DatasetContractRef, checkDatasetVersion int) int {
	if checkDatasetVersion > 0 {
		return checkDatasetVersion
	}
	matchCount := 0
	matchVersion := 0
	for _, dc := range dataContracts {
		if dc.Dataset != dataset {
			continue
		}
		matchCount++
		matchVersion = dc.Version
		if matchCount > 1 {
			break
		}
	}
	if matchCount == 1 {
		return matchVersion
	}
	return 1
}

