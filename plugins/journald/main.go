/*
Copyright (C) 2022 The Falco Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	sdj "github.com/coreos/go-systemd/sdjournal"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/extractor"
	"github.com/falcosecurity/plugin-sdk-go/pkg/sdk/plugins/source"
	"github.com/invopop/jsonschema"
)

type JournalEvent struct {
	Message                 string `json:"MESSAGE"`
	Priority                string `json:"PRIORITY"`
	SyslogFacility          string `json:"SYSLOG_FACILITY"`
	SyslogIdentifier        string `json:"SYSLOG_IDENTIFIER"`
	SyslogPid               string `json:"SYSLOG_PID"`
	SyslogTimestamp         string `json:"SYSLOG_TIMESTAMP"`
	BootID                  string `json:"_BOOT_ID"`
	CapEffective            string `json:"_CAP_EFFECTIVE"`
	Cmdline                 string `json:"_CMDLINE"`
	Comm                    string `json:"_COMM"`
	Exe                     string `json:"_EXE"`
	Gid                     string `json:"_GID"`
	Hostname                string `json:"_HOSTNAME"`
	MachineID               string `json:"_MACHINE_ID"`
	Pid                     string `json:"_PID"`
	SelinuxContext          string `json:"_SELINUX_CONTEXT"`
	SourceRealtimeTimestamp string `json:"_SOURCE_REALTIME_TIMESTAMP"`
	SystemdCgroup           string `json:"_SYSTEMD_CGROUP"`
	SystemdInvocationID     string `json:"_SYSTEMD_INVOCATION_ID"`
	SystemdSlice            string `json:"_SYSTEMD_SLICE"`
	SystemdUnit             string `json:"_SYSTEMD_UNIT"`
	Transport               string `json:"_TRANSPORT"`
	UID                     string `json:"_UID"`
}

type JournalPlugin struct {
	plugins.BasePlugin
}

type JournalInstance struct {
	source.BaseInstance
	journalConfig sdj.JournalReaderConfig
	journalReader *sdj.JournalReader
	buf           []byte
}

func init() {
	p := &JournalPlugin{}
	extractor.Register(p)
	source.Register(p)
}

// Info displays information of the plugin to Falco plugin framework
func (journalPlugin *JournalPlugin) Info() *plugins.Info {
	return &plugins.Info{
		ID:                 9,
		Name:               "journal",
		Description:        "Journald Log Events",
		Contact:            "github.com/falcosecurity/plugins/",
		Version:            "0.1.0",
		RequiredAPIVersion: "1.0.0",
		EventSource:        "journal",
	}
}

func (journalPlugin *JournalPlugin) InitSchema() *sdk.SchemaInfo {
	reflector := jsonschema.Reflector{
		RequiredFromJSONSchemaTags: true, // all properties are optional by default
		AllowAdditionalProperties:  true, // unrecognized properties don't cause a parsing failures
	}
	if schema, err := reflector.Reflect(&JournalPlugin{}).MarshalJSON(); err == nil {
		return &sdk.SchemaInfo{
			Schema: string(schema),
		}
	}
	return nil
}

func (journalPlugin *JournalPlugin) Init(config string) error {
	err := json.Unmarshal([]byte(config), &journalPlugin)
	if err != nil {
		return err
	}
	return nil
}

func (journalPlugin *JournalPlugin) Fields() []sdk.FieldEntry {
	return []sdk.FieldEntry{
		{Type: "string", Name: "journal.message", Desc: "Message"},
		{Type: "string", Name: "journal.priority", Desc: "Priority"},
		{Type: "string", Name: "journal.syslog_facility", Desc: "Syslog Facility"},
		{Type: "string", Name: "journal.syslog_identifier", Desc: "Syslog Identifier"},
		{Type: "string", Name: "journal.syslog_pid", Desc: "Syslog Pid"},
		{Type: "string", Name: "journal.syslog_timestamp", Desc: "Syslog Timestamp"},
		{Type: "string", Name: "journal.boot_id", Desc: "Boot Id"},
		{Type: "string", Name: "journal.cap_effective", Desc: "Cap Effective"},
		{Type: "string", Name: "journal.cmdline", Desc: "Cmdline"},
		{Type: "string", Name: "journal.comm", Desc: "Comm"},
		{Type: "string", Name: "journal.exe", Desc: "Exe"},
		{Type: "string", Name: "journal.gid", Desc: "Gid"},
		{Type: "string", Name: "journal.hostname", Desc: "Hostname"},
		{Type: "string", Name: "journal.machine_id", Desc: "Machine Id"},
		{Type: "string", Name: "journal.pid", Desc: "Pid"},
		{Type: "string", Name: "journal.selinux_context", Desc: "SELinux Context"},
		{Type: "string", Name: "journal.source_realtime_timestamp", Desc: "Source Realtime Timestamp"},
		{Type: "string", Name: "journal.systemd_cgroup", Desc: "Systemd Cgroup"},
		{Type: "string", Name: "journal.systemd_invocation_id", Desc: "Systemd Invocation Id"},
		{Type: "string", Name: "journal.systemd_slice", Desc: "Systemd Slice"},
		{Type: "string", Name: "journal.systemd_unit", Desc: "Systemd Unit"},
		{Type: "string", Name: "journal.transport", Desc: "Transport"},
		{Type: "string", Name: "journal.uid", Desc: "Uid"},
	}
}

func (journalPlugin *JournalPlugin) Extract(req sdk.ExtractRequest, evt sdk.EventReader) error {

	var data JournalEvent

	rawData, err := ioutil.ReadAll(evt.Reader())
	if err != nil {
		return err
	}

	err = json.Unmarshal(rawData, &data)
	if err != nil {
		return err
	}

	switch req.Field() {
	case "journal.message":
		req.SetValue(data.Message)
	case "journal.priority":
		req.SetValue(data.Priority)
	case "journal.syslog_facility":
		req.SetValue(data.SyslogFacility)
	case "journal.syslog_identifier":
		req.SetValue(data.SyslogIdentifier)
	case "journal.syslog_pid":
		req.SetValue(data.SyslogPid)
	case "journal.syslog_timestamp":
		req.SetValue(data.SyslogTimestamp)
	case "journal.boot_id":
		req.SetValue(data.BootID)
	case "journal.cap_effective":
		req.SetValue(data.CapEffective)
	case "journal.cmdline":
		req.SetValue(data.Cmdline)
	case "journal.comm":
		req.SetValue(data.Comm)
	case "journal.exe":
		req.SetValue(data.Exe)
	case "journal.gid":
		req.SetValue(data.Gid)
	case "journal.hostname":
		req.SetValue(data.Hostname)
	case "journal.machine_id":
		req.SetValue(data.MachineID)
	case "journal.pid":
		req.SetValue(data.Pid)
	case "journal.selinux_context":
		req.SetValue(data.SelinuxContext)
	case "journal.source_realtime_timestamp":
		req.SetValue(data.SourceRealtimeTimestamp)
	case "journal.systemd_cgroup":
		req.SetValue(data.SystemdCgroup)
	case "journal.systemd_invocation_id":
		req.SetValue(data.SystemdInvocationID)
	case "journal.systemd_slice":
		req.SetValue(data.SystemdSlice)
	case "journal.systemd_unit":
		req.SetValue(data.SystemdUnit)
	case "journal.transport":
		req.SetValue(data.Transport)
	case "journal.uid":
		req.SetValue(data.UID)
	default:
		return fmt.Errorf("no known field: %s", req.Field())
	}

	return nil
}

func (journalPlugin *JournalPlugin) Open(params string) (source.Instance, error) {
	var params_map map[string]uint64
	json.Unmarshal([]byte(params), &params_map)
	config := sdj.JournalReaderConfig{
		NumFromTail: params_map["num_from_trail"],
		Formatter:   Formatter,
	}

	j, err := sdj.NewJournalReader(config)
	if err != nil {
		return nil, fmt.Errorf("Cannot init journal reader")
	}

	var msg = make([]byte, 64*1<<(10))

	return &JournalInstance{
		journalConfig: config,
		journalReader: j,
		buf:           msg,
	}, nil
}

func (journalPlugin *JournalPlugin) String(in io.ReadSeeker) (string, error) {
	evtBytes, err := ioutil.ReadAll(in)
	if err != nil {
		return "", err
	}
	evtStr := string(evtBytes)

	return fmt.Sprintf("%v", evtStr), nil
}

func (journalInstance *JournalInstance) NextBatch(pState sdk.PluginState, evts sdk.EventWriters) (int, error) {
	c, err := journalInstance.journalReader.Read(journalInstance.buf)
	if err != nil {
		return 0, sdk.ErrTimeout
	}

	if c > 0 {
		if _, err = evts.Get(0).Writer().Write(journalInstance.buf[:c]); err != nil {
			return 0, fmt.Errorf("Cannot write event")
		}

		return 1, nil
	}

	return 0, sdk.ErrTimeout
}

func (journalInstance *JournalInstance) Close() {
	journalInstance.journalReader.Close()
}

func Formatter(entry *sdj.JournalEntry) (string, error) {
	jsonString, err := json.Marshal(entry.Fields)
	if err != nil {
		return "", fmt.Errorf("Cannot marshal entry fields")
	}
	return string(jsonString) + "\n", nil
}

func main() {}
