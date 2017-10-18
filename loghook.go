// Copyright © 2017 Okta, Inc
// Author: Joel Franusic <joel.franusic@okta.com>
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package main

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
    "strconv"
    "time"

    "github.com/getlantern/osversion"
    log "github.com/sirupsen/logrus"
)

var rfc5988 = regexp.MustCompile(`^<(.*?)>;\srel="(.*?)"`)

type logClient struct {
    oktaOrgUrl   string
    apiToken     string
    retrySeconds string
}

type oktaLogEvent struct {
    DisplayMessage string    `json:"displayMessage"`
    EventType      string    `json:"eventType"`
    Published      time.Time `json:"published"`
    Severity       string    `json:"severity"`
    UUID           string    `json:"uuid"`
    Version        string    `json:"version"`
}

type logEventResult struct {
    logClient *logClient
    events    []json.RawMessage
    offset    int
    nextLink  string
    Since     time.Time
    err       error
}

func (l *logEventResult) log(err error) error {
    log.Warning("Error: ", err)
    l.err = err
    return err
}

func (l *logEventResult) getEvents(loc string) error {
    log.Debug("Events since: ", l.Since)
    if loc == "" {
        u, err := url.Parse(l.logClient.oktaOrgUrl + "/api/v1/logs")
        if err != nil {
            log.Fatal(err)
        }
        if !l.Since.IsZero() {
            q := u.Query()
            q.Set("since", l.Since.Format(time.RFC3339))
            q.Set("until", time.Now().UTC().Format(time.RFC3339))
            u.RawQuery = q.Encode()
        }
        loc = u.String()
    }
    log.Debug("Getting URL: ", loc)
    req, err := http.NewRequest("GET", loc, nil)
    if err != nil {
        return l.log(err)
    }

    req.Header.Add("Accept", "application/json")
    req.Header.Add("Authorization", "SSWS "+l.logClient.apiToken)
    req.Header.Add("Cache-Control", "no-cache")
    req.Header.Add("Content-Type", "application/json")
    req.Header.Add("User-Agent", userAgent)

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return l.log(err)
    }
    defer resp.Body.Close()

    for _, value := range resp.Header["Link"] {
        match := rfc5988.FindStringSubmatch(value)
        link, rel := match[1], match[2]
        if rel == "next" {
            l.nextLink = link
        }
    }
    l.offset = 0
    l.events = make([]json.RawMessage, 100)
    err = json.NewDecoder(resp.Body).Decode(&l.events)
    if err != nil {
        return l.log(err)
    }
    return nil
}

func (l *logEventResult) Next() bool {
    if l.offset == -1 {
        err := l.getEvents("")
        if err != nil {
            log.Warning("Error:", err)
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
        } else {
            return true
        }
    }
    // Try again next time
    l.offset = -1
    return false
}

func (l *logEventResult) Get() (*oktaLogEvent, *[]byte) {
    raw := []byte(l.events[l.offset])
    l.offset += 1

    var oktaEvent oktaLogEvent
    err := json.Unmarshal(raw, &oktaEvent)
    if err != nil {
        l.log(err)
        return nil, nil
    }
    return &oktaEvent, &raw
}

func (l *logEventResult) Sleep() {
    ts := l.Since.Format(time.RFC3339)
    log.WithFields(log.Fields{"last_seen": ts}).Debug("Sleeping")
    var retrySeconds int
    retrySeconds, err := strconv.Atoi(l.logClient.retrySeconds)
    if err != nil {
        retrySeconds = 15
    }
    time.Sleep(time.Second * time.Duration(retrySeconds))
}

func (c *logClient) Tail() (*logEventResult, error) {
    logEvent := &logEventResult{
        logClient: c,
        offset:    -1,
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

func eventProcessorInit() eventProcessor {
    processor := eventProcessor{}
    processor.Handlers = []eventHandler{}
    return processor
}

func (p *eventProcessor) Add(expression, destination string) {
    re, err := regexp.Compile(expression)
    if err != nil {
        log.Fatal("Error compiling Regular Expression: ", err)
    }
    url, err := url.Parse(destination)
    if err != nil {
        log.Fatal("Error parsing destination URL: ", err)
    }
    p.Handlers = append(p.Handlers, eventHandler{re, url})
    log.Info(fmt.Sprintf("Sending events matching '%s' to '%s'", expression, destination))
}

func (p *eventProcessor) Process(event *oktaLogEvent, raw *[]byte) {
    for _, handler := range p.Handlers {
        re, url := handler.Expression, handler.URL
        log.WithFields(log.Fields{
            "UUID":      event.UUID,
            "Published": event.Published.Format(time.RFC3339),
            "EventType": event.EventType,
        }).Info("Event")
        if re.MatchString(event.EventType) {
            sendWebhook(url, event, raw)
        }
    }
}

func (p *eventProcessor) LoadConfig(filename string) {
    f, err := os.Open(filename)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    records, _ := csv.NewReader(f).ReadAll()
    for _, record := range records {
        p.Add(record[0], record[1])
    }
}

func makeUserAgent() string {
    goVersion := strings.Replace(runtime.Version(), "go", "", -1)
    osVersion, err := osversion.GetString()
    if err != nil {
        osVersion = "ERROR"
    }
    userAgent := fmt.Sprintf("%s/%s go/%s %s/%s",
        "loghook", // clientName
        "0.0.4",   // Version
        goVersion,
        runtime.GOOS,
        osVersion,
    )
    return userAgent
}

var userAgent = makeUserAgent()

func sendWebhook(url *url.URL, event *oktaLogEvent, payload *[]byte) error {
    log.Debug("POSTing to URL:", url)

    req, err := http.NewRequest("POST", url.String(), bytes.NewReader(*payload))
    req.Header.Set("User-Agent", userAgent)
    req.Header.Set("Content-Type", "application/json")

    client := &http.Client{}
    resp, err := client.Do(req)
    if err != nil {
        log.Error(err)
    }
    defer resp.Body.Close()

    log.WithFields(log.Fields{"EventType": event.EventType, "URL": url}).Info("Match found")
    return nil
}


func main() {
    log.SetOutput(os.Stdout)
    log.SetLevel(log.InfoLevel)

    oktaLogClient := &logClient{
        oktaOrgUrl:   os.Getenv("OKTA_ORG_URL"),
        apiToken:     os.Getenv("OKTA_API_KEY"),
        retrySeconds: os.Getenv("LOGHOOK_RETRY_SECONDS"),
    }
    logEvents, _ := oktaLogClient.Tail()
    logEvents.Since = time.Now().UTC().Add(time.Minute * -2)

    eventProcessor := eventProcessorInit()
    eventProcessor.LoadConfig("loghook.csv")

    log.Info("Started polling for events at: ", oktaLogClient.oktaOrgUrl)
    for {
        for logEvents.Next() {
            logEvent, raw := logEvents.Get()
            if !logEvent.Published.IsZero() {
                logEvents.Since = logEvent.Published.Add(time.Second * 1)
            }
            eventProcessor.Process(logEvent, raw)
        }
        if logEvents.err != nil {
            log.Warning("Error:", logEvents.err)
            break
        }
        logEvents.Sleep()
    }
}
