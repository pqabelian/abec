package api

func SerializeAutMetadata(autMetadata *AutMetadata) ([]byte, error) {
	return autMetadata.Serialize()
}

// end of codes
