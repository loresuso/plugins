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

/* Reference "dummy" plugin, similar to the dummy plugin, but written
 * in C++. It uses the C++ sdk ../../sdk/cpp/falcosecurity_plugin.h
 * and implements classes that derive from
 * falcosecurity::source_plugin and falcosecurity::plugin_instance. */

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "nlohmann/json.hpp"

#include <falcosecurity_plugin.h>
#include <rocksdb/db.h>

#include "hash_calculator.h"

using ROCKSDB_NAMESPACE::DB;

using json = nlohmann::json;

class hashing_plugin : public falcosecurity::source_plugin {
public:
	hashing_plugin();
	virtual ~hashing_plugin();

	// All of these are from falcosecurity::source_plugin_iface.
	void get_info(falcosecurity::plugin_info &info) override;
	ss_plugin_rc init(const char *config) override;
	void destroy() override;
	falcosecurity::plugin_instance *create_instance(falcosecurity::source_plugin &plugin) override;
	std::string event_to_string(const uint8_t *data, uint32_t datalen) override;
	bool extract_str(const ss_plugin_event &evt, const std::string &field, const std::string &arg, std::string &extract_val) override;
	bool extract_u64(const ss_plugin_event &evt, const std::string &field, const std::string &arg, uint64_t &extract_val) override;

private:
	// A copy of the config provided to init()
	std::string m_config;

};

class hashing_instance : public falcosecurity::plugin_instance {
public:
	hashing_instance(hashing_plugin &plugin);
	virtual ~hashing_instance();

	// All of these are from falcosecurity::plugin_instance_iface.
	ss_plugin_rc open(const char *params) override;
	void close() override;
	ss_plugin_rc next(falcosecurity::plugin_event &evt) override;

private:
	// The plugin that created this instance
	hashing_plugin &m_plugin;

	// All of these reflect potential internal state for the
	// instance.

	// Copy of the init params from plugin_open()
	std::string m_params;
};

hashing_plugin::hashing_plugin()
{

};

hashing_plugin::~hashing_plugin()
{
};


void hashing_plugin::get_info(falcosecurity::plugin_info &info)
{
	info.name = "hashing";
	info.description = "Reference plugin for educational purposes";
	info.contact = "github.com/falcosecurity/plugins";
	info.version = "0.2.1";
	info.event_source = "hashing";
	info.fields = {
		{FTYPE_UINT64, "dummy.divisible", true, "Return 1 if the value is divisible by the provided divisor, 0 otherwise"},
		{FTYPE_UINT64, "dummy.value", false, "The sample value in the event"},
		{FTYPE_STRING, "dummy.strvalue", false, "The sample value in the event, as a string"}
	};
}

ss_plugin_rc hashing_plugin::init(const char *config)
{
	m_config = config != NULL ? config : "";

	std::cout << " ----------" << std::endl;

	std::string res;
	hash_calculator hc;
	hc.checksum("/home/ubuntu/malwares/DHLx11.apk", hash_calculator::HT_MD5, &res);
	std::cout << res << std::endl;

	std::cout << " ----------" << std::endl;

	// Config is optional. In this case defaults are used.
	if(m_config == "" || m_config == "{}")
	{
		return SS_PLUGIN_SUCCESS;
	}

	json obj;

	try {
		obj = json::parse(m_config);
	}
	catch (std::exception &e)
	{
		set_last_error(e.what());
		return SS_PLUGIN_FAILURE;
	}

	return SS_PLUGIN_SUCCESS;
}

void hashing_plugin::destroy()
{
}

falcosecurity::plugin_instance *hashing_plugin::create_instance(falcosecurity::source_plugin &plugin)
{
	return new hashing_instance((hashing_plugin &) plugin);

}

std::string hashing_plugin::event_to_string(const uint8_t *data, uint32_t datalen)
{
	// The string representation of an event is a json object with the sample
	std::string rep = "{\"sample\": ";
	rep.append((char *) data, datalen);
	rep += "}";

	return rep;
}

bool hashing_plugin::extract_str(const ss_plugin_event &evt, const std::string &field, const std::string &arg, std::string &extract_val)
{
	if (field == "dummy.strvalue")
	{
		extract_val.assign((char *) evt.data, evt.datalen);
		return true;
	}

	return false;
}

bool hashing_plugin::extract_u64(const ss_plugin_event &evt, const std::string &field, const std::string &arg, uint64_t &extract_val)
{
	std::string sample((char *) evt.data, evt.datalen);
	uint64_t isample = std::stoi(sample);

	if(field == "dummy.divisible")
	{
		uint64_t divisor = std::stoi(arg);
		if ((isample % divisor) == 0)
		{
			extract_val = 1;
		}
		else
		{
			extract_val = 0;
		}

		return true;
	}
	else if (field == "dummy.value")
	{
		extract_val = isample;

		return true;
	}

	return false;
}

hashing_instance::hashing_instance(hashing_plugin &plugin)
	: m_plugin(plugin)
{
}

hashing_instance::~hashing_instance()
{
}

ss_plugin_rc hashing_instance::open(const char *params)
{
	m_params = params;
	
	DB *db;

	return SS_PLUGIN_SUCCESS;
}

void hashing_instance::close()
{
}

ss_plugin_rc hashing_instance::next(falcosecurity::plugin_event &evt)
{
	// Let the plugin framework assign timestamps
	evt.ts = (uint64_t) -1;

	return SS_PLUGIN_SUCCESS;
}

// This macro creates the plugin_xxx functions that comprise the
// source plugin API. It creates hashing_plugin and hashing_instance
// objects as needed and translates the plugin API calls into the
// methods in falcosecurity::source_plugin_iface and
// falcosecurity::plugin_instance_iface.
GEN_SOURCE_PLUGIN_API_HOOKS(hashing_plugin, hashing_instance)
