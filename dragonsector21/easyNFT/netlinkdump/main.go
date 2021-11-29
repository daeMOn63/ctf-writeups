package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/mdlayher/netlink"
	"github.com/ti-mo/netfilter"
)

// https://elixir.bootlin.com/linux/v5.15.5/source/net/netfilter/nf_tables_api.c#L7838
// https://elixir.bootlin.com/linux/v5.15.5/source/include/uapi/linux/netfilter/nf_tables.h#L118

var messageTypeNames = []string{
	"NFT_MSG_NEWTABLE",
	"NFT_MSG_GETTABLE",
	"NFT_MSG_DELTABLE",
	"NFT_MSG_NEWCHAIN",
	"NFT_MSG_GETCHAIN",
	"NFT_MSG_DELCHAIN",
	"NFT_MSG_NEWRULE",
	"NFT_MSG_GETRULE",
	"NFT_MSG_DELRULE",
	"NFT_MSG_NEWSET",
	"NFT_MSG_GETSET",
	"NFT_MSG_DELSET",
	"NFT_MSG_NEWSETELEM",
	"NFT_MSG_GETSETELEM",
	"NFT_MSG_DELSETELEM",
	"NFT_MSG_NEWGEN",
	"NFT_MSG_GETGEN",
	"NFT_MSG_TRACE",
	"NFT_MSG_NEWOBJ",
	"NFT_MSG_GETOBJ",
	"NFT_MSG_DELOBJ",
	"NFT_MSG_GETOBJ_RESET",
	"NFT_MSG_NEWFLOWTABLE",
	"NFT_MSG_GETFLOWTABLE",
	"NFT_MSG_DELFLOWTABLE",
	"NFT_MSG_MAX",
}

var attributeTypeNames = map[string][]string{
	"NFT_MSG_NEWGEN": {
		"NFTA_GEN_UNSPEC",
		"NFTA_GEN_ID",
		"NFTA_GEN_PROC_PID",
		"NFTA_GEN_PROC_NAME",
	},
	"NFT_MSG_NEWTABLE": {
		"NFTA_TABLE_UNSPEC",
		"NFTA_TABLE_NAME",
		"NFTA_TABLE_FLAGS",
		"NFTA_TABLE_USE",
		"NFTA_TABLE_HANDLE",
		"NFTA_TABLE_PAD",
		"NFTA_TABLE_USERDATA",
		"NFTA_TABLE_OWNER",
		"__NFTA_TABLE_MAx",
	},
	"NFT_MSG_NEWCHAIN": {
		"NFTA_CHAIN_UNSPEC",
		"NFTA_CHAIN_TABLE",
		"NFTA_CHAIN_HANDLE",
		"NFTA_CHAIN_NAME",
		"NFTA_CHAIN_HOOK",
		"NFTA_CHAIN_POLICY",
		"NFTA_CHAIN_USE",
		"NFTA_CHAIN_TYPE",
		"NFTA_CHAIN_COUNTERS",
		"NFTA_CHAIN_PAD",
		"NFTA_CHAIN_FLAGS",
		"NFTA_CHAIN_ID",
		"NFTA_CHAIN_USERDATA",
		"__NFTA_CHAIN_MAX",
	},
	"NFT_MSG_GETSET": {
		"NFTA_SET_UNSPEC",
		"NFTA_SET_TABLE",
		"NFTA_SET_NAME",
		"NFTA_SET_FLAGS",
		"NFTA_SET_KEY_TYPE",
		"NFTA_SET_KEY_LEN",
		"NFTA_SET_DATA_TYPE",
		"NFTA_SET_DATA_LEN",
		"NFTA_SET_POLICY",
		"NFTA_SET_DESC",
		"NFTA_SET_ID",
		"NFTA_SET_TIMEOUT",
		"NFTA_SET_GC_INTERVAL",
		"NFTA_SET_USERDATA",
		"NFTA_SET_PAD",
		"NFTA_SET_OBJ_TYPE",
		"NFTA_SET_HANDLE",
		"NFTA_SET_EXPR",
		"NFTA_SET_EXPRESSIONS",
		"__NFTA_SET_MAX",
	},
	"NFT_MSG_NEWSET": {
		"NFTA_SET_UNSPEC",
		"NFTA_SET_TABLE",
		"NFTA_SET_NAME",
		"NFTA_SET_FLAGS",
		"NFTA_SET_KEY_TYPE",
		"NFTA_SET_KEY_LEN",
		"NFTA_SET_DATA_TYPE",
		"NFTA_SET_DATA_LEN",
		"NFTA_SET_POLICY",
		"NFTA_SET_DESC",
		"NFTA_SET_ID",
		"NFTA_SET_TIMEOUT",
		"NFTA_SET_GC_INTERVAL",
		"NFTA_SET_USERDATA",
		"NFTA_SET_PAD",
		"NFTA_SET_OBJ_TYPE",
		"NFTA_SET_HANDLE",
		"NFTA_SET_EXPR",
		"NFTA_SET_EXPRESSIONS",
		"__NFTA_SET_MAX",
	},
	"NFT_MSG_GETSETELEM": {
		"NFTA_SET_ELEM_UNSPEC",
		"NFTA_SET_ELEM_KEY",
		"NFTA_SET_ELEM_DATA",
		"NFTA_SET_ELEM_FLAGS",
		"NFTA_SET_ELEM_TIMEOUT",
		"NFTA_SET_ELEM_EXPIRATION",
		"NFTA_SET_ELEM_USERDATA",
		"NFTA_SET_ELEM_EXPR",
		"NFTA_SET_ELEM_PAD",
		"NFTA_SET_ELEM_OBJREF",
		"NFTA_SET_ELEM_KEY_END",
		"NFTA_SET_ELEM_EXPRESSIONS",
		"__NFTA_SET_ELEM_MAX",
	},
	"NFT_MSG_NEWSETELEM": {
		"NFTA_SET_ELEM_LIST_UNSPEC",
		"NFTA_SET_ELEM_LIST_TABLE",
		"NFTA_SET_ELEM_LIST_SET",
		"NFTA_SET_ELEM_LIST_ELEMENTS",
		"NFTA_SET_ELEM_LIST_SET_ID",
		"__NFTA_SET_ELEM_LIST_MAX",
	},
	"NFT_MSG_GETFLOWTABLE": {
		"NFTA_FLOWTABLE_UNSPEC",
		"NFTA_FLOWTABLE_TABLE",
		"NFTA_FLOWTABLE_NAME",
		"NFTA_FLOWTABLE_HOOK",
		"NFTA_FLOWTABLE_USE",
		"NFTA_FLOWTABLE_HANDLE",
		"NFTA_FLOWTABLE_PAD",
		"NFTA_FLOWTABLE_FLAGS",
		"__NFTA_FLOWTABLE_MAX",
	},
	"NFT_MSG_NEWRULE": {
		"NFTA_RULE_UNSPEC",
		"NFTA_RULE_TABLE",
		"NFTA_RULE_CHAIN",
		"NFTA_RULE_HANDLE",
		"NFTA_RULE_EXPRESSIONS",
		"NFTA_RULE_COMPAT",
		"NFTA_RULE_POSITION",
		"NFTA_RULE_USERDATA",
		"NFTA_RULE_PAD",
		"NFTA_RULE_ID",
		"NFTA_RULE_POSITION_ID",
		"NFTA_RULE_CHAIN_ID",
		"__NFTA_RULE_MAX",
	},
}

func main() {
	f, err := os.Open("hex_netlink.dump")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	var messages []netlink.Message

	for scanner.Scan() {
		packetHex := scanner.Text()

		d, err := hex.DecodeString(packetHex)
		if err != nil {
			panic(err)
		}

		// packet may contains multiple messages, so split on size
		for {
			size := binary.LittleEndian.Uint32(d[:4])

			packet := d
			if len(d) > int(size) {
				packet = d[:size]
			}
			d = d[size:]

			msg := netlink.Message{}
			if err := msg.UnmarshalBinary(packet); err != nil {
				panic(fmt.Errorf("failed to unmarshal: %v - packet: %x", err, d))
			}

			messages = append(messages, msg)
			if len(d) == 0 {
				break
			}
		}
	}

	fmt.Printf("Parsed %d messages\n", len(messages))
	for _, m := range messages {
		header, attrs, err := netfilter.UnmarshalNetlink(m)
		if err != nil {
			panic(err)
		}
		// lookup message name from its message type
		fmt.Printf("%s\n", messageTypeNames[header.MessageType])
		for _, attr := range attrs {
			// lookup attribute name from its message type and attribute type
			// or just keep default string repr if no name exists
			attributeName := attr.String()
			attrNames, ok := attributeTypeNames[messageTypeNames[header.MessageType]]
			if ok {
				attributeName = attrNames[int(attr.Type)]
			}

			switch attributeName {
			case "NFTA_SET_ELEM_LIST_ELEMENTS":
				fmt.Printf("\t%s\n", attributeName)
				printAttrRecursive(attr.Data, 2)
			case "NFTA_RULE_EXPRESSIONS":
				fmt.Printf("\t%s\n", attributeName)
				printAttrRecursive(attr.Data, 2)
			default:
				fmt.Printf("\t%s - %q\n", attributeName, attr.Data)
			}
		}
	}

	// for i, m := range messages {
	// 	h, attrs, err := netfilter.UnmarshalNetlink(m)
	// 	if err != nil {
	// 		panic(err)
	// 	}

	// 	if h.SubsystemID == netfilter.NFSubsysNone {
	// 		continue
	// 	}

	// 	// fmt.Printf("Message #%d %s %s\n", i, m.Header.Type.String(), m.Header.Flags.String())
	// 	fmt.Printf("Message #%d: %s\n", i, messageTypeNames[h.MessageType])
	// 	for _, a := range attrs {
	// 		attrNames, ok := attributeTypeNames[messageTypeNames[h.MessageType]]
	// 		attributeName := a.String()
	// 		if ok {
	// 			attributeName = attrNames[int(a.Type)]
	// 		}

	// 		switch attributeName {
	// 		case "NFTA_RULE_EXPRESSIONS":
	// 			fmt.Printf("\t%s\n", attributeName)
	// 			attrs, err := netfilter.UnmarshalAttributes(a.Data)
	// 			if err != nil {
	// 				panic(err)
	// 			}

	// 			for _, sa := range attrs {
	// 				elts, err := netfilter.UnmarshalAttributes(sa.Data)
	// 				if err != nil {
	// 					panic(err)
	// 				}
	// 				for _, e := range elts {
	// 					if e.Type == 1 {
	// 						fmt.Printf("\t\t- Name: %s\n", e.Data)
	// 					} else {
	// 						// fmt.Printf("\t\t- Value: %q\n", e.Data)
	// 						selts, err := netfilter.UnmarshalAttributes(e.Data)
	// 						if err != nil {
	// 							panic(err)
	// 						}
	// 						for _, se := range selts {
	// 							fmt.Printf("\t\t# %s %x\n", se.String(), se.Data)
	// 						}
	// 					}
	// 				}
	// 			}
	// 		case "NFTA_CHAIN_HOOK":
	// 			fmt.Printf("\t%s\n", attributeName)
	// 			attrs, err := netfilter.UnmarshalAttributes(a.Data)
	// 			if err != nil {
	// 				panic(err)
	// 			}

	// 			for _, sa := range attrs {
	// 				fmt.Printf("\t\t# %s %x\n", sa.String(), sa.Data)
	// 			}
	// 		case "NFTA_SET_ELEM_LIST_ELEMENTS":
	// 			fmt.Printf("\t%s\n", attributeName)

	// 			// elts, err := nftables.ElementsFromMsg(m)
	// 			// if err != nil {
	// 			// 	panic(err)
	// 			// }
	// 			// for _, e := range elts {
	// 			// 	fmt.Printf("\t\tKey: %q, Value: %q\n", e.Key, e.Val)
	// 			// }
	// 		default:
	// 			fmt.Printf("\t%s %q\n", attributeName, a.Data)
	// 		}
	// 	}

	// }
}

func printAttrRecursive(data []byte, level int) {
	attrs, err := netfilter.UnmarshalAttributes(data)
	if err != nil {
		return
	}

	for _, attr := range attrs {
		if len(attr.Data) > 0 {
			fmt.Printf("%sType: %d: %q\n", strings.Repeat("\t", level), attr.Type, attr.Data)
			printAttrRecursive(attr.Data, level+1)
		}
	}
}
