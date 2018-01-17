package main

import (
	"fmt"
	"os"
	"os/signal"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/honeycombio/honeyaws/logbucket"
	"github.com/honeycombio/honeyaws/options"
	"github.com/honeycombio/honeyaws/publisher"
	"github.com/honeycombio/honeyaws/state"
	libhoney "github.com/honeycombio/libhoney-go"
)

var (
	opt        = &options.Options{}
	BuildID    string
	versionStr string
)

func init() {
	// set the version string to our desired format
	if BuildID == "" {
		versionStr = "dev"
	} else {
		versionStr = BuildID
	}

	// init libhoney user agent properly
	libhoney.UserAgentAddition = "honeycloudtrail/" + versionStr
}

func cmdCloudTrail(args []string) error {
	// TODO: Would be nice to have this more highly configurable.
	//
	// Will just use environment config right now, e.g., default profile.
	sess := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	cloudtrailSvc := cloudtrail.New(sess, nil)

	listTrailsResp, err := cloudtrailSvc.DescribeTrails(&cloudtrail.DescribeTrailsInput{})

	if len(args) > 0 {
		switch args[0] {
		case "ls", "list":
			for _, trailSummary := range listTrailsResp.DescribeTrails.TrailList {
				fmt.Println(*trailSummary.TrailARN)
			}
			return nil

		case "ingest":
			if opt.WriteKey == "" {
				logrus.Fatal(`--writekey must be set to the proper write key for the Honeycomb team.
Your write key is available at https://ui.honeycomb.io/account`)
			}

			trailNames := args[1:]

			if len(trailNames) == 0 {
				for _, trail := range listTrailsResp.DescribeTrails.TrailList {
					trailNames.append(trailNames, *trail.Name)
				}
			}

			trailListResp, err := cloudtrailSvc.DescribeTrails(&cloudtrail.DescribeTrailsInput{
				TrailNameList: aws.StringSlice(trailNames),
			})
			if err != nil {
				fmt.Fprintln(os.Stderr, "Error getting trail descriptions: ", err)
				os.Exit(1)
			}

			var stater state.Stater

			if opt.HighAvail {
				svc := dynamodb.New(sess)
				input := &dynamodb.DescribeTableInput{
					TableName: aws.String("HoneyELBAccessLogBuckets"),
				}
				_, err := svc.DescribeTable(input)
				if err != nil {
					// For some reason, we cannot write to
					// the table or access it
					logrus.Fatal(`--high-availability requires an existing DynamoDB tabled named HoneyELBAccessLogBuckets, please refer to the README.`)
				}

				stater = state.NewDynamoDBStater(sess, logbucket.AWSCloudTrail)
				logrus.Info("High availability enabled - using DynamoDB")

			} else {
				stater = state.NewFileStater(opt.StateDir, logbucket.AWSCloudTrail)
			}

			downloadsCh := make(chan state.DownloadedObject)
			defaultPublisher := publisher.NewHoneycombPublisher(opt, stater, publisher.NewCloudTrailEventParser(opt.SampleRate))

			for _, trail := range trailListResp.TrailList {
				if strings.Compare(trail.S3Bucket, "") == 0 {
					fmt.Fprintf(os.Stderr, `%q does not currently have an S3 bucket that it is writing logs to. Please enable them to use the ingest tool. 

For reference see this link:
https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-create-and-update-a-trail.html `, trail.Name)

					os.Exit(1)
				}
				bucket := trail.S3Bucket
				logrus.WithFields(logrus.Fields{
					"bucket": bucket,
					"name":   name,
				}).Info("Access logs are enabled for CloudTrail trails")

				cloudtrailDownloader := logbucket.NewCloudTrailDownloader(bucket, trail.prefix, trail.Name)
				downloader := logbucket.NewDownloader(sess, stater, cloudtrailDownloader)
				go downloader.Download(downloadsCh)
			}

			signalCh := make(chan os.Signal)
			signal.Notify(signalCh, os.Interrupt)
			go func() {
				<-signalCh
				logrus.Fatal("Exiting due to interrupt.")
			}()

			for {
				download := <-downloadsCh
				if err := defaultPublisher.Publish(download); err != nil {
					logrus.WithField("object", download).Error("Cannot properly publish downloaded object")
				}
			}

		}

	}

	if err != nil {
		return err
		os.Exit(1)
	}
}

func main() {
	flagParser := flag.NewParser(opt, flag.Default)
	args, err := flagParser.Parse()
	if err != nil {
		os.Exit(1)
	}

	if opt.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	formatter := &logrus.TextFormatter{
		FullTimestamp: true,
	}
	logrus.SetFormatter(formatter)

	logrus.WithField("version", BuildID).Debug("Program starting")

	if opt.Dataset == "aws-$SERVICE-access" {
		opt.Dataset = "aws-cloudtrail-access"
	}

	if _, err := os.Stat(opt.StateDir); os.IsNotExist(err) {
		logrus.WithField("dir", opt.StateDir).Fatal("Specified state directory does not exist")
	}

	if opt.Version {
		fmt.Println("honeycloudtrail version", versionStr)
		os.Exit(0)
	}

	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `Usage: `+os.Args[0]+` [--flags] [ls|ingest] [CloudTrail distribution IDs...]

Use '`+os.Args[0]+` --help' to see available flags.`)
		os.Exit(1)
	}

	if err := cmdCloudTrail(args); err != nil {
		fmt.Fprintln(os.Stderr, "Error: ", err)
		os.Exit(1)
	}
}
