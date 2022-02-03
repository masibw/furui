package convert

func ActionToString(action uint8) string {
	switch action {
	case 1:
		return "dropped"
	case 2:
		return "passed"
	default:
		return "unknown"
	}
}
