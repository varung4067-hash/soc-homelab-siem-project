import win32evtlog
import xmltodict


SYS_MON_LOG = "Microsoft-Windows-Sysmon/Operational"


def get_sysmon_events(limit=20):
    """
    Reads Sysmon Event ID 1 (Process Create)
    Returns parsed events as dictionaries
    """

    server = "localhost"
    logtype = SYS_MON_LOG

    hand = win32evtlog.OpenEventLog(server, logtype)
    flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

    events = win32evtlog.ReadEventLog(hand, flags, 0)
    parsed_events = []

    for event in events:
        try:
            xml = win32evtlog.EvtRender(
                event, win32evtlog.EvtRenderEventXml
            )
            data = xmltodict.parse(xml)

            system = data["Event"]["System"]
            event_id = int(system["EventID"]["#text"])

            # We only want Sysmon Event ID 1 (Process Create)
            if event_id != 1:
                continue

            event_data = {}
            for item in data["Event"]["EventData"]["Data"]:
                event_data[item["@Name"]] = item.get("#text", "")

            parsed_events.append(event_data)

            if len(parsed_events) >= limit:
                break

        except Exception:
            continue

    return parsed_events
