#pragma once

#include <algorithm>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace option {

class CommandHelp {
    enum Type {
        TYPE_NAME,
        TYPE_ALIAS,
        TYPE_VALUE,
        TYPE_MSG,

        TYPE_MAX
    };

    std::vector<std::string> data[TYPE_MAX];
    unsigned int maxLen;

  public:
    CommandHelp() : maxLen(0) {}
    ~CommandHelp() {}

    void Add(std::string name, std::string alias, std::string value, std::string msg) {
        data[TYPE_NAME].push_back(name);
        data[TYPE_ALIAS].push_back(alias);
        data[TYPE_VALUE].push_back(value);
        data[TYPE_MSG].push_back(msg);
        unsigned int len = name.length();
        if (!alias.empty()) {
            len += alias.length();
            len += 2; // ", ".length
        }
        if (!value.empty()) {
            len += value.length();
            len += 1; // " ".length
        }
        if (len > maxLen) {
            maxLen = len;
        }
    }
    void Show() {
        std::cerr << "Options:" << std::endl;
        for (unsigned int i = 0; i < data[TYPE_NAME].size(); i++) {
            // show name and alias
            std::string msg = std::string("  ") + data[TYPE_NAME][i];
            unsigned int len = data[TYPE_NAME][i].length();
            if (!data[TYPE_ALIAS][i].empty()) {
                msg += std::string(", ") + data[TYPE_ALIAS][i];
                len += data[TYPE_ALIAS][i].length() + 2;
            }
            msg += " ";

            // show value
            msg += data[TYPE_VALUE][i];
            len += data[TYPE_VALUE][i].length();
            for (auto i = len; i < maxLen; i++) {
                msg += " ";
            }
            msg += " ";

            // show message
            msg += data[TYPE_MSG][i];

            std::cerr << msg << std::endl;
        }
    }
};

// This class deal with command line argument
class OpsParse {
    std::map<std::string, std::string> def_none;
    std::map<std::string, std::string> def_val;
    std::string helpMsg;
    CommandHelp command;

    std::vector<std::string> opt_none;
    std::map<std::string, std::string> opt_val;

  public:
    OpsParse() {}
    ~OpsParse() {}

    void AddHelpMessage(std::string helpMsg) {
        this->helpMsg += helpMsg + "\n";
    }

    bool AddDefine(std::string name, std::string alias, bool requireVal, std::string helpMsg) {
        if (name.empty()) {
            return false;
        }
        if (requireVal) { // the option requires argument
            def_val.insert(std::map<std::string, std::string>::value_type(name, helpMsg));
            command.Add(name, alias, "<value>", helpMsg);
            if (!alias.empty()) {
                return def_val.insert(std::map<std::string, std::string>::value_type(alias, helpMsg)).second;
            }
        } else {
            def_none.insert(std::map<std::string, std::string>::value_type(name, helpMsg));
            command.Add(name, alias, "", helpMsg);
            if (!alias.empty()) {
                return def_none.insert(std::map<std::string, std::string>::value_type(alias, helpMsg)).second;
            }
        }
        return true; // successfully registered
    }

    bool ParseArguments(int argc, char *argv[]) {
        for (int i = 1; i < argc; i++) {
            std::string val = argv[i];
            if (def_val.count(val) != 0) {
                if (i == argc - 1)
                    return false;
                opt_val.insert(std::map<std::string, std::string>::value_type(val, argv[i + 1]));
                i++;
            } else {
                if (def_none.count(val) != 0)
                    opt_none.push_back(val);
                else
                    return false;
            }
        }
        return true;
    }

    void ShowHelpMessage() {
        std::cerr << helpMsg << std::endl;
        command.Show();
    }

    std::vector<std::string> GetOptionNone() const { return opt_none; }
    std::map<std::string, std::string> GetOptionValue() const { return opt_val; }
};
}; // namespace option