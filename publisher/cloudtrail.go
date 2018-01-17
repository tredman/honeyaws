package publisher

import (
	"compress/gzip"
	"encoding/json"
	"io"
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
	linesCh := make(chan string)
	records := make([]map[string]interface{})

	go np.ProcessLines(linesCh, out, nil)

	f, err := os.Open(obj.Filename)
	if err != nil {
		return err
	}

	fs, err := f.Stat()
	if err != nil {
		return err
	}

	defer f.Close()

	r, err := gzip.NewReader(f)
	if err != nil {
		return err
	}

	fileBuf := make([]byte, fs.Size())
	fileJson, err := io.ReadFull(r, fileBuf)
	json.Unmarshal(fileJson, &records)

	linesCh <- records

	close(linesCh)

	return nil
}

func (ep *CloudFrontEventParser) DynSample(in <-chan event.Event, out chan<- event.Event) {
	return nil
}
