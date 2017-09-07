// Copyright © 2017 Okta, Inc 
// Author: Joel Franusic <joel.franusic@okta.com>
package cmd

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/getlantern/osversion"
	"github.com/spf13/cobra"
	log "github.com/sirupsen/logrus"
)

// runCmd represents the run command
var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run the log monitor",
	Run: func(cmd *cobra.Command, args []string) {
		run(
			cmd.Flag("oktaDomain").Value.String(),
			cmd.Flag("oktaApiKey").Value.String(),
			cmd.Flag("configFile").Value.String(),
		)
	},
}

func init() {
	RootCmd.AddCommand(runCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// runCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// runCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")

}


type logClient struct {
	fqdn     string
	apiToken string
	BaseURL  string
}

type oktaLogEvent struct {
	Actor struct {
		ID          string      `json:"id"`
		Type        string      `json:"type"`
		AlternateID string      `json:"alternateId"`
		DisplayName string      `json:"displayName"`
		DetailEntry interface{} `json:"detailEntry"`
	} `json:"actor"`
	Client struct {
		UserAgent struct {
			RawUserAgent string `json:"rawUserAgent"`
			Os           string `json:"os"`
			Browser      string `json:"browser"`
		} `json:"userAgent"`
		Zone                string      `json:"zone"`
		Device              string      `json:"device"`
		ID                  interface{} `json:"id"`
		IPAddress           string      `json:"ipAddress"`
		GeographicalContext struct {
			City        string `json:"city"`
			State       string `json:"state"`
			Country     string `json:"country"`
			PostalCode  string `json:"postalCode"`
			Geolocation struct {
				Lat float64 `json:"lat"`
				Lon float64 `json:"lon"`
			} `json:"geolocation"`
		} `json:"geographicalContext"`
	} `json:"client"`
	AuthenticationContext struct {
		AuthenticationProvider interface{} `json:"authenticationProvider"`
		CredentialProvider     interface{} `json:"credentialProvider"`
		CredentialType         interface{} `json:"credentialType"`
		Issuer                 interface{} `json:"issuer"`
		Interface              interface{} `json:"interface"`
		AuthenticationStep     int         `json:"authenticationStep"`
		ExternalSessionID      string      `json:"externalSessionId"`
	} `json:"authenticationContext"`
	DisplayMessage string `json:"displayMessage"`
	EventType      string `json:"eventType"`
	Outcome        struct {
		Result string `json:"result"`
		Reason string `json:"reason"`
	} `json:"outcome"`
	Published       time.Time `json:"published"`
	SecurityContext struct {
		AsNumber interface{} `json:"asNumber"`
		AsOrg    interface{} `json:"asOrg"`
		Isp      interface{} `json:"isp"`
		Domain   interface{} `json:"domain"`
		IsProxy  interface{} `json:"isProxy"`
	} `json:"securityContext"`
	Severity     string `json:"severity"`
	DebugContext struct {
		DebugData struct {
			RequestURI string `json:"requestUri"`
		} `json:"debugData"`
	} `json:"debugContext"`
	LegacyEventType interface{} `json:"legacyEventType"`
	Transaction     struct {
		Type   string `json:"type"`
		ID     string `json:"id"`
		Detail struct {
		} `json:"detail"`
	} `json:"transaction"`
	UUID    string `json:"uuid"`
	Version string `json:"version"`
	Request struct {
		IPChain []struct {
			IP                  string `json:"ip"`
			GeographicalContext struct {
				City        string `json:"city"`
				State       string `json:"state"`
				Country     string `json:"country"`
				PostalCode  string `json:"postalCode"`
				Geolocation struct {
					Lat float64 `json:"lat"`
					Lon float64 `json:"lon"`
				} `json:"geolocation"`
			} `json:"geographicalContext"`
			Version string      `json:"version"`
			Source  interface{} `json:"source"`
		} `json:"ipChain"`
	} `json:"request"`
	Target []struct {
		ID          string `json:"id"`
		Type        string `json:"type"`
		AlternateID string `json:"alternateId"`
		DisplayName string `json:"displayName"`
		DetailEntry struct {
			PolicyType string `json:"policyType"`
		} `json:"detailEntry"`
	} `json:"target"`
}

type logEventResult struct {
	events   []oktaLogEvent
	offset   int
	nextLink string
	fqdn     string
	apiToken string
	baseUrl  string
	Since    time.Time
	err      error
}

func (l *logEventResult) getEvents(loc string) error {
	log.Debug("Events since: ", l.Since)
	if loc == "" {
		u, _ := url.Parse(l.baseUrl + "/api/v1/logs")
		if !l.Since.IsZero() {
			q := u.Query()
			q.Set("since", l.Since.Format(time.RFC3339))
			q.Set("until", "now")
			u.RawQuery = q.Encode()
		}
		loc = u.String()
	}
	log.Debug("Getting URL: ", loc)
	req, err := http.NewRequest("GET", loc, nil)
	if err != nil {
		log.Warning("Error: ", err)
		l.err = err
		return err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "SSWS " + l.apiToken)
	req.Header.Add("Cache-Control", "no-cache")
	req.Header.Add("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Warning("Error: ", err)
		l.err = err
		return err
	}
	defer resp.Body.Close()

	nextLink := ""
	rfc5988 := regexp.MustCompile(`^<(.*?)>;\srel="(.*?)"`)
	for _, value := range resp.Header["Link"] {
		match := rfc5988.FindStringSubmatch(value)
		link, rel := match[1], match[2]
		if rel == "next" {
			nextLink = link
		}
	}
	l.nextLink = nextLink
	l.offset = 0
	l.events = make([]oktaLogEvent, 100)
	err = json.NewDecoder(resp.Body).Decode(&l.events)
	if err != nil {
		log.Warning("Error: ", err)
		l.err = err
		return err
	}
	return nil
}

func (l *logEventResult) Next() bool {
	if l.offset == -1 {
		err := l.getEvents("")
		if err != nil {
			log.Warning("Error:" , err)
			return false
		}
	}
	if l.offset < len(l.events) {
		return true
	} else if l.nextLink != "" {
		err := l.getEvents(l.nextLink)
		if err != nil {
			log.Warning("Error: ", err)
			return false
		}
	} 
	return false
}

func (l *logEventResult) Get() *oktaLogEvent {
	returnValue := &l.events[l.offset]
	l.offset += 1
	return returnValue
}

func logClientInit(fqdn, apiToken string) *logClient {
	log.Debug("Setting FQDN to: ", fqdn)
	baseUrl := fmt.Sprintf("https://%s", fqdn)
	client := &logClient{
		fqdn: fqdn,
		BaseURL: baseUrl,
		apiToken: apiToken,
	}
	return client
}

func (c *logClient) Tail() (*logEventResult, error) {
	logEvent := &logEventResult{
		fqdn: c.fqdn,
		baseUrl: c.BaseURL,
		apiToken: c.apiToken,
		offset: -1,
	}
	return logEvent, nil
}

type eventHandler struct {
	Expression *regexp.Regexp
	URL        *url.URL
}

type eventProcessor struct {
	Handlers []eventHandler
}

func eventProcessorInit() (eventProcessor, error) {
	processor := eventProcessor{}
	processor.Handlers = []eventHandler{}
	return processor, nil
}

func (p *eventProcessor) Add(expression, destination string) {
	// FIXME: Add error handling here
	re, _ := regexp.Compile(expression)
	// FIXME: Add error handling here
	url, _ := url.Parse(destination)
	handler := eventHandler{re, url}
	p.Handlers = append(p.Handlers, handler)
}

func makeUserAgent() string {
	goVersion := strings.Replace(runtime.Version(), "go", "", -1)
	osVersion, err := osversion.GetString()
	if err != nil {
		osVersion = "ERROR"
	}
	userAgent := fmt.Sprintf("%s/%s go/%s %s/%s",
		"loghook", // clientName
		"0.0.1",   // Version
		goVersion,
		runtime.GOOS,
		osVersion,
	)
	return userAgent
}

var userAgent = makeUserAgent()

func sendWebhook(url *url.URL, event *oktaLogEvent) error {
    log.Debug("POSTing to URL:", url)

    payload, _ := json.Marshal(event)
    req, err := http.NewRequest("POST", url.String(), bytes.NewBuffer(payload))
    req.Header.Set("User-Agent", userAgent)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        panic(err)
    }
    defer resp.Body.Close()

    // fmt.Println("response Status:", resp.Status)
    // fmt.Println("response Headers:", resp.Header)
	log.WithFields(log.Fields{"EventType": event.EventType, "URL": url}).Info("Match found")
	return nil
}

func (p *eventProcessor) Process(event *oktaLogEvent) {
	for _, handler := range p.Handlers {
		re, url := handler.Expression, handler.URL
		log.WithFields(log.Fields{
			"UUID":event.UUID,
			"Published": event.Published.Format(time.RFC3339),
			"EventType": event.EventType,
		}).Info("Event")
		if re.MatchString(event.EventType) {
			sendWebhook(url, event)
		}
	}
}

func (p *eventProcessor) LoadConfig(filename string) {
	f, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    cfg := csv.NewReader(f)
	records, _ := cfg.ReadAll()

	for _, record := range records {
		p.Add(record[0], record[1])
	}
}

func run(fqdn, apiToken, configFile string) {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
	
	logClient := logClientInit(fqdn, apiToken)
	eventProcessor, _ := eventProcessorInit()
	eventProcessor.LoadConfig(configFile)

	recently := time.Now()
	recently = recently.Add(time.Minute * -1)
	logEvents, _ := logClient.Tail()
	logEvents.Since = recently

	log.Info("Started")
	last := time.Time{}
	for {
		for logEvents.Next() {
			logEvent := logEvents.Get()
			current := logEvent.Published.Add(time.Second * 1)
			if current.After(last) {
				last = current
			}

			eventProcessor.Process(logEvent)
		}
		if logEvents.err != nil {
			log.Warning("Error:", logEvents.err)
			break
		}
		if last.IsZero() {
			last = time.Now()
		}
		// FIXME: .Next() should not require me to do this:
		logEvents, _ = logClient.Tail()
		logEvents.Since = last
		ts := last.Format(time.RFC3339)
		log.WithFields(log.Fields{"last_seen": ts}).Debug("Sleeping")
		time.Sleep(time.Second * 10)
	}
}
