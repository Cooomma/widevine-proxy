package widevineproxy

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

func TestGetContentKey(t *testing.T) {
	key, _ := hex.DecodeString(testKey)
	iv, _ := hex.DecodeString(testIV)
	keyGenerator := &FakeKeyGoverner{}

	logger := logrus.New()
	logger.SetLevel(logrus.DebugLevel)
	logger.SetFormatter(&logrus.TextFormatter{
		ForceColors:     true,
		FullTimestamp:   true,
		TimestampFormat: time.RFC822,
	})
	logger.SetOutput(colorable.NewColorableStdout())

	wv := NewWidevineProxy(key, iv, "widevine_test", keyGenerator, logger)
	contentID := "testing"

	// Make the request to generate or get a content key.
	policy := Policy{
		ContentID: contentID,
		Tracks:    []string{"SD", "HD", "AUDIO"},
		DRMTypes:  []string{"WIDEVINE"},
		Policy:    "default",
	}
	resp, err := wv.GetContentKey(contentID, policy)
	assert.NoError(t, err)

	if resp.Status != "OK" {
		t.Error()
	}
}
