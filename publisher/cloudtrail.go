package publisher

import (
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
	"os"

	"github.com/Sirupsen/logrus"
	dynsampler "github.com/honeycombio/dynsampler-go"
	"github.com/honeycombio/honeyaws/state"
	"github.com/honeycombio/honeytail/event"
)

type CloudTrailEventParser struct {
	sampler dynsampler.Sampler
}

func NewCloudTrailEventParser(sampleRate int) *CloudTrailEventParser {
	ep := &CloudTrailEventParser{
		sampler: &dynsampler.AvgSampleRate{
			ClearFrequencySec: 300,
			GoalSampleRate:    sampleRate,
		},
	}

	if err := ep.sampler.Start(); err != nil {
		logrus.WithField("err", err).Fatal("Couldn't start dynamic sampler")
	}

	return ep
}

func (ep *CloudTrailEventParser) ParseEvents(obj state.DownloadedObject, out chan<- event.Event) error {
	linesCh := make(chan []map[string]interface{})
	records := make([]map[string]interface{}, 0)

	f, err := os.Open(obj.Filename)
	if err != nil {
		return err
	}

	defer f.Close()

	r, err := gzip.NewReader(f)
	if err != nil {
		return err
	}

	fileJson, err := ioutil.ReadAll(r)
	json.Unmarshal(fileJson, &records)

	linesCh <- records

	close(linesCh)

	return nil
}

func (ep *CloudTrailEventParser) DynSample(in <-chan event.Event, out chan<- event.Event) {
}
