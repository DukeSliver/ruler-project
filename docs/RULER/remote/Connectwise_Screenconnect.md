# Connectwise/Screenconnect

Currently named Connectwise, but old Screenconnect name still persists

## Event logs

|Event Log | Event ID | Provider | Message
|-|-|-|-
|Application.evtx|100|`ScreenConnect Client (<random>)`* or `Screenconnect`| <account name> connected
|Application.evtx|101|`ScreenConnect Client (<random>)`* or `Screenconnect`| <account name> disconnected
|Application.evtx|201|`ScreenConnect Client (<random>)`* or `Screenconnect`| Transferred files with action '<action>'
|Application.evtx|200|`ScreenConnect Client (<random>)`* or `Screenconnect`| "Executed command of length" (but no command is provided)

* There is also a Service install (EID: 7045 System evtx, EID: 4697 Security evtx) on ScreenConnect install.
	* The command line of the service install reveals the local agent configurations, importantly, the control relay server found in the `&h` parameter. This can be used to determine whether a ConnectWise control agent is under the control of your organization. For an example see the command-line section in the behavior sandbox report for cc4279e9aecdec28151a75a0e999d3b0 in VirusTotal.
* No Evtxecmd map can cover older versions this due to engineering decisions. The result will be in the Payload column.
* Later versions can be mapped, and the account ID will be in the payload (mapped to executable path).
* Previous versions had all of the above events in EventID == 1. However, more recent testing showed 100, 101, and 201. The 4th row may still be Event ID == 1. Additional testing needed.

## Application files

* User config - `C:\Windows\SysWOW64\config\systemprofile\AppData\Local\ScreenConnect Client (<random>)\user.config`
* `%PROGRAMDATA%\ScreenConnect Client (<random>)\`
* `%PROGRAMFILES(x86)%\ScreenConnect Client (<random>)\`
* `%SYSTEMROOT%\temp\screenconnect\[version]\`
* `%USERPROFILE%\Documents\ConnectWiseControl\captures\`
* File execution - `%USERPROFILE%\Documents\ConnectWiseControl\Temp\malware.exe`
* File Transfers - `%USERPROFILE%\Documents\ConnectWiseControl\Files\`
* Scripts - `%SYSTEMROOT%\temp`

## Cloud Console Events
It's possible to obtain audit logs from the ConnectWise Control cloud console and it's possible to forward the logs to a SIEM.

The two main types of events are those that audit the agents, and those that audit the cloud console. Agent logs will include things like file uploads, command executions, and connections, while the cloud logs will include things like user authentications to the cloud console and password resets.

### Console Audit Events
#### User Failed First Factor
The user provided an incorrect password.

```json
{
    "Event": {
        "EventID": "eef5a8f4-55d3-4a59-bb1d-1f6e00418280",
        "EventType": "LoginAttempt",
        "Time": "2024-03-05T19:04:56.0884794Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "PasswordInvalid",
        "UserSource": "",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/Login?ReturnUrl=%2fAdministration%3fTab%3d2&Reason=6",
        "UserName": "test-user"
    },
    "SecurityEvent": {
        "EventID": "eef5a8f4-55d3-4a59-bb1d-1f6e00418280",
        "EventType": "LoginAttempt",
        "Time": "2024-03-05T19:04:56.0884794Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "PasswordInvalid",
        "UserSource": "",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/Login?ReturnUrl=%2fAdministration%3fTab%3d2&Reason=6",
        "UserName": "test-user"
    }
}
```
#### User Challenge Authentication
A local (InternalMembershipProvider) user provided the correct password but was presented with an additional factor as a challenge, setting the result of the authentication to "OneTimePasswordRequired". OTP is the only MFA factor available for local cloud accounts.

```json
{
    "Event": {
        "EventID": "3fb5a3bb-736a-4ea9-b88a-18420dfaa64a",
        "EventType": "LoginAttempt",
        "Time": "2024-03-05T18:57:47.9688045Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "OneTimePasswordRequired",
        "UserSource": "InternalMembershipProvider",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/Login?ReturnUrl=%2fAdministration%3fTab%3d7&Reason=6",
        "UserName": "test-user"
    },
    "SecurityEvent": {
        "EventID": "3fb5a3bb-736a-4ea9-b88a-18420dfaa64a",
        "EventType": "LoginAttempt",
        "Time": "2024-03-05T18:57:47.9688045Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "OneTimePasswordRequired",
        "UserSource": "InternalMembershipProvider",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/Login?ReturnUrl=%2fAdministration%3fTab%3d7&Reason=6",
        "UserName": "test-user"
    }
}
```

#### User Failed Challenge Authentication
After providing the correct password, the local (InternalMembershipProvider) user provided an incorrect OTP code and failed the challenge.

```json
{
    "Event": {
        "EventID": "9f648cff-d17d-4e76-a0e6-af427078f27a",
        "EventType": "LoginAttempt",
        "Time": "2024-03-05T18:57:56.6230518Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "OneTimePasswordInvalid",
        "UserSource": "InternalMembershipProvider",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/Login?ReturnUrl=%2fAdministration%3fTab%3d7&Reason=6",
        "UserName": "test-user"
    },
    "SecurityEvent": {
        "EventID": "9f648cff-d17d-4e76-a0e6-af427078f27a",
        "EventType": "LoginAttempt",
        "Time": "2024-03-05T18:57:56.6230518Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "OneTimePasswordInvalid",
        "UserSource": "InternalMembershipProvider",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/Login?ReturnUrl=%2fAdministration%3fTab%3d7&Reason=6",
        "UserName": "test-user"
    }
}
```

#### User Successful Authentication
A local (InternalMembershipProvider) user was successfully authenticated to the cloud console.
```json
{
    "Event": {
        "EventID": "8e8bdfc2-278e-4933-bd8e-4dd8b0661409",
        "EventType": "LoginAttempt",
        "Time": "2024-03-05T19:05:15.0059763Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "Success",
        "UserSource": "InternalMembershipProvider",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/Login?ReturnUrl=%2fAdministration%3fTab%3d2&Reason=6",
        "UserName": "test-user"
    },
    "SecurityEvent": {
        "EventID": "8e8bdfc2-278e-4933-bd8e-4dd8b0661409",
        "EventType": "LoginAttempt",
        "Time": "2024-03-05T19:05:15.0059763Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "Success",
        "UserSource": "InternalMembershipProvider",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/Login?ReturnUrl=%2fAdministration%3fTab%3d2&Reason=6",
        "UserName": "test-user"
    }
}
```
#### User Password Reset
A local (InternalMembershipProvider) user reset their password. No event is generated for a user resetting the password of another user.
```json
{
    "Event": {
        "EventID": "4572c540-43bb-44c2-ba38-76b4f46058f4",
        "EventType": "ChangePasswordAttempt",
        "Time": "2024-03-05T19:14:23.0510168Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "Success",
        "UserSource": "InternalMembershipProvider",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/ChangePassword",
        "UserName": "test-user"
    },
    "SecurityEvent": {
        "EventID": "4572c540-43bb-44c2-ba38-76b4f46058f4",
        "EventType": "ChangePasswordAttempt",
        "Time": "2024-03-05T19:14:23.0510168Z",
        "NetworkAddress": "35.173.127.53",
        "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
        "OperationResult": "Success",
        "UserSource": "InternalMembershipProvider",
        "UrlReferrer": "https://nfrllcagents.screenconnect.com/ChangePassword",
        "UserName": "test-user"
    }
}
```

### Agent Audit Events
These events are incredibly verbose so they've been cut down for the sake of the reader. The below table contains the most common elements found in these events that can be used to get better context, especially directionality. ^[6]^ ^[7]^

On directionality, for most events this is determined by the "Connection" element which contains details about the host that connected to the session and triggered the event, however, in cases where the connection is the result of a guest machine checking in due to an action performed by the host machine, the true "actor" source IP will be contained in the "Session.ActiveConnections" element. 

| Field                                                 | Description
|-|-|
| Event.EventType                  | The action that was performed.|
| Event.Data                       | Event specific data, such as the name of a file that was copied, or the command that was sent to a Guest machine.|
| Connection.NetworkAddress |  The source IP of the machine responsible for triggering the event.|
| Connection.ProcessType           | The type of actor that triggered the event: The "Host" actor is the one that takes control of the remote ScreenConnect agent, and the "Guest" actor is the remote ScreenConnect agent.|
| ActiveConnections.NetworkAddress | The source IP of a connected session. Can be the IP of either the Guest or Host depending on the value of the adjacent "ProcessType" field which will be either Host(1) or Guest(2).|
| ActiveConnections.ProcessType    | The types of actors that were actively connected to a given session. The presence of both the "Host"(1), and "Guest"(2) actors indicates the Guest is being controlled by the Host in some way. When the "Guest"(2) connection is alone, it usually means the ScreenConnect agent is just checking in, or that it's responding with the results of a previous command.|
| GuestInfo.GuestNetworkAddress    | The public IP address associated with the remote ScreenConnect agent (Guest).|



#### Connected
These events are generated when either the guest or host connects to a session.

```json
{
    "Event": {
        "EventID": "8f864576-815c-4fbd-8fad-49555f07d43b",
        "EventType": "Connected",
        "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T20:40:22.651748Z",
        "Host": "",
        "Data": ""
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T20:40:22.651748Z",
        "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
        "ProcessType": "Host",
        "ParticipantName": "Cloud Account Administrator",
        "NetworkAddress": "35.173.127.53",
    },

    "Session": {
        "ActiveConnections": [
            {
                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
                "ProcessType": 2,
                "ParticipantName": "",
                "ClientType": 1,
                "NetworkAddress": "54.174.92.215"
            },
            {
                "ConnectedTime": "2024-03-05T20:40:22.651748Z",
                "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
                "ProcessType": 1,
                "ParticipantName": "Cloud Account Administrator",
                "ClientType": 1,
                "NetworkAddress": "35.173.127.53"
            }
        ],
    }
	"CorrelationEvent": null,
}
```

#### Disconnected
These events are generated when either the guest or host disconnects from a session. They are useful in determining the length of time a host machine was connected to a session. There are no correlation keys, so to correlate these events with their "Connected" counterparts, one must use the username, host, and time.

```json
{
    "Event": {
        "EventID": "2f09acf0-783d-47ea-8942-2cfd547b669d",
        "EventType": "Disconnected",
        "ConnectionID": "81d99cc7-5848-4d6e-b032-6f1fbc7ac17a",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T21:48:04.1332832Z",
        "Host": "",
        "Data": ""
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T21:40:38.8939629Z",
        "ConnectionID": "81d99cc7-5848-4d6e-b032-6f1fbc7ac17a",
        "ProcessType": "Host",
        "ParticipantName": "Cloud Account Administrator",
        "NetworkAddress": "35.173.127.53"
    },
    "CorrelationEvent": null
}
```

#### CopiedFiles
Files can be transferred via the dedicated graphical tool in the ConnectWise Control client, by graphically clicking and dragging to and from the interactive client open with the remote agent, and simply by using the clipboard.

The direction of the file transfer is determined by the "ProcessType" field within the "Connection" node. The "ProcessType" field is set to "Guest" when the file transfer is from the remote ScreenConnect agent to the local host. When the file transfer is from the local host to the remote ScreenConnect agent this field is set to "Host".

In cases where the file is being transferred from the "Guest" machine, the "Host" machine, the true actor's IP address will be in the Session.ActiveConnections[].NetworkAddress element where the Session.ActiveConnections[].ProcessType is "1" for Host.

<sub>A file is copied from the remote agent (Guest) to the local machine (Host).</sub>
```json
{
    "Event": {
        "EventID": "0ecaa6e4-625b-4434-9912-bccee8bd06e8",
        "EventType": "CopiedFiles",
        "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T20:49:10.9044214Z",
        "Host": "",
        "Data": "ScreenConnect.ClientSetup.msi"
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
        "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
        "ProcessType": "Guest",
        "ParticipantName": "",
        "NetworkAddress": "54.174.92.215"
    },
	"Session":{
		"GuestNetworkAddress": "54.174.92.215",
		"ActiveConnections": [
	            {
	                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
	                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
	                "ProcessType": 2,
	                "ParticipantName": "",
	                "ClientType": 1,
	                "NetworkAddress": "54.174.92.215"
	            },
	            {
	                "ConnectedTime": "2024-03-05T20:40:22.651748Z",
	                "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
	                "ProcessType": 1,
	                "ParticipantName": "Cloud Account Administrator",
	                "ClientType": 1,
	                "NetworkAddress": "35.173.127.53"
	            }
	        ]
		}
	"CorrelationEvent": null
}
```

<sub>A file is copied from the local host to the remote agent.</sub>
```json
{
    "Event": {
        "EventID": "b917d678-2f79-4b30-9a74-f90b59d6ab1a",
        "EventType": "CopiedFiles",
        "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T20:49:25.8541669Z",
        "Host": "",
        "Data": "ping-google.bat"
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T20:40:22.651748Z",
        "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
        "ProcessType": "Host",
        "ParticipantName": "Cloud Account Administrator",
        "NetworkAddress": "35.173.127.53"
    },
    "CorrelationEvent": null,
	"Session":{
		"GuestNetworkAddress": "54.174.92.215",
		"ActiveConnections": [
            {
                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
                "ProcessType": 2,
                "ParticipantName": "",
                "ClientType": 1,
                "NetworkAddress": "54.174.92.215"
            },
            {
                "ConnectedTime": "2024-03-05T20:40:22.651748Z",
                "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
                "ProcessType": 1,
                "ParticipantName": "Cloud Account Administrator",
                "ClientType": 1,
                "NetworkAddress": "35.173.127.53"
            }
        ]
	}
	"CorrelationEvent": null
}
```


#### DraggedFiles
This event is triggered when files are graphically "dragged" from one host to the other through the ConnectWise ScreenConnect client.

<sub>A file is transferred from the remote agent to the local host.</sub>
```json
{
    "Event": {
        "EventID": "38aaea8f-c6b5-433f-b647-09baefa14614",
        "EventType": "DraggedFiles",
        "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T20:41:30.9483813Z",
        "Host": "",
        "Data": "Google Chrome.lnk"
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
        "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
        "ProcessType": "Guest",
        "ParticipantName": "",
        "NetworkAddress": "54.174.92.215"
    },
    "Session":{
	    "GuestNetworkAddress": "54.174.92.215",
	    "ActiveConnections": [
            {
                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
                "ProcessType": 2,
                "ParticipantName": "",
                "ClientType": 1,
                "NetworkAddress": "54.174.92.215"
            },
            {
                "ConnectedTime": "2024-03-05T20:40:22.651748Z",
                "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
                "ProcessType": 1,
                "ParticipantName": "Cloud Account Administrator",
                "ClientType": 1,
                "NetworkAddress": "35.173.127.53"
            }
        ]
    }
    "CorrelationEvent": null
}
```


<sub>A file is transferred from the local host to the remote agent.</sub>
```json
{
    "Event": {
        "EventID": "001268e6-69ac-4cda-bc27-1e0cd8c6727d",
        "EventType": "DraggedFiles",
        "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T20:41:26.3556977Z",
        "Host": "",
        "Data": "ping-google.bat"
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T20:40:22.651748Z",
        "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
        "ProcessType": "Host",
        "ParticipantName": "Cloud Account Administrator",
        "NetworkAddress": "35.173.127.53"
    },
    "Session":{
	    "GuestNetworkAddress": "54.174.92.215",
	    "ActiveConnections": [
	            {
	                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
	                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
	                "ProcessType": 2,
	                "ParticipantName": "",
	                "ClientType": 1,
	                "NetworkAddress": "54.174.92.215"
	            },
	            {
	                "ConnectedTime": "2024-03-05T20:40:22.651748Z",
	                "ConnectionID": "74239dae-4a4d-4279-8774-4f650b9227b3",
	                "ProcessType": 1,
	                "ParticipantName": "Cloud Account Administrator",
	                "ClientType": 1,
	                "NetworkAddress": "35.173.127.53"
	            }
	        ]
    }
    "CorrelationEvent": null,
}
```

#### RanCommand
This is the best event for finding out not only what command was run, but also for finding out its output. The 200 Event ID Application logs don't provide this level of visibility into the commands that were executed.

Since the `RanCommand` event is a result of the Guest machine checking in with the result of a command, it won't have the user or true source IP that initiated the command so you have to find the correlated `QueuedCommand` event to get the user so that you can get the correlated authentication event containing the true source IP.

```json
{
    "Event": {
        "EventID": "33345555-93e5-4e79-a940-9cb31a366e89",
        "EventType": "RanCommand",
        "ConnectionID": "151ea5e6-8f03-48e5-94de-671a37bbb3e8",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T19:45:46.2868459Z",
        "Host": "",
        "Data": "C:\\Windows\\system32>whoami\r\nnt authority\\system\r\n"
    },
    "Connection": {
        "ConnectedTime": "2024-03-04T20:29:37.0197258Z",
        "ConnectionID": "151ea5e6-8f03-48e5-94de-671a37bbb3e8",
        "ProcessType": "Guest",
        "ParticipantName": "",
        "NetworkAddress": "52.55.14.45"
    },
    "CorrelationEvent": null
}
```

#### QueuedCommand
A remote command was queued for processing (server-side). The "Queued*" events don't have information about the result of the command like their after-action counterparts because these events are triggered before the action is taken. The `QueuedCommand` event is useful for instances where the action was not taken for some reason, such as the ScreenConnect agent not checking in. This event is also useful for finding out the ConnectWise control user responsible for staging a command.

In cases where the command was queued through the ConnectWise Control web interface instead of through an active connection to a guest machine through the ConnectWise Control client, there won't be a source IP in this event. Instead, to find the responsible source IP, one must use the `Event.Host` field which shows the responsible ConnectWise Control user. This can be used to find the correlated cloud console authentication event which will have the responsible source IP.

```json
{
    "Event": {
        "EventID": "0cef89eb-4aa8-4522-a388-eaae47b6683e",
        "EventType": "QueuedCommand",
        "ConnectionID": "00000000-0000-0000-0000-000000000000",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T20:18:45.8442428Z",
        "Host": "Cloud Account Administrator",
        "Data": "echo \"Multi host/site command!\""
    },
    "Connection": null,
    "Session": {
        "GuestInfo": {
            "MachineName": "WEF",
        "QueuedEvents": [
            {
                "EventID": "0cef89eb-4aa8-4522-a388-eaae47b6683e",
                "EventType": 44,
                "ConnectionID": "00000000-0000-0000-0000-000000000000",
                "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
                "Time": "2024-03-05T20:18:45.8442428Z",
                "Host": "Cloud Account Administrator",
                "Data": "echo \"Multi host/site command!\""
            }
        ],
        "QueuedEventType": "QueuedCommand",
        "QueuedEventHost": "Cloud Account Administrator",
        "QueuedEventData": "echo \"Multi host/site command!\"",
    "CorrelationEvent": null
}
```



#### QueuedTool
This event indicates that an executable or script that was saved in the ConnectWise Control "Toolbox" was set to execute. It's possible to schedule script runs for multiple agents at once using this feature. Each agent which receives the script will generate its own event. There's no direct correlation between events in the same queue, but it's simple enough to determine how many hosts a script or tool was deployed to with a distinct count of the hosts in the `Session.GuestInfo.MachineName` field by each filename in the `Event.Data` field.

```json
{
    "Event": {
        "EventID": "12568e71-12b8-4731-b467-6909a6fe3ccb",
        "EventType": "QueuedTool",
        "ConnectionID": "00000000-0000-0000-0000-000000000000",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T20:01:48.6578128Z",
        "Host": "Cloud Account Administrator",
        "Data": "ping-google.bat"
    },
    "Connection": null,
    "Session": {
        "GuestInfo": {
            "MachineName": "WEF",
        "QueuedEvents": [
            {
                "EventID": "12568e71-12b8-4731-b467-6909a6fe3ccb",
                "EventType": 47,
                "ConnectionID": "00000000-0000-0000-0000-000000000000",
                "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
                "Time": "2024-03-05T20:01:48.6578128Z",
                "Host": "Cloud Account Administrator",
                "Data": "ping-google.bat"
            }
        ],
        "QueuedEventType": "QueuedTool",
        "QueuedEventHost": "Cloud Account Administrator",
        "QueuedEventData": "ping-google.bat",
    "CorrelationEvent": null,
}
```

#### QueuedElevatedTool
This event indicates that an executable or script that was saved in the ConnectWise Control "Toolbox" was set to execute with administrative privileges. It's possible to schedule script runs for multiple agents at once using this feature. Each agent which receives the script will generate its own event. There's no direct correlation between events in the same queue, but it's simple enough to determine how many hosts a script or tool was deployed to with a distinct count of the hosts in the `Session.GuestInfo.MachineName` field by each filename in the `Event.Data` field.

```json
{
    "Event": {
        "EventID": "e68a21a6-8b8f-4834-a8f4-c51809a3b82d",
        "EventType": "QueuedElevatedTool",
        "ConnectionID": "00000000-0000-0000-0000-000000000000",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T19:56:07.221262Z",
        "Host": "Cloud Account Administrator",
        "Data": "ping-google.bat"
    },
    "Connection": null,
    "Session": {
        "GuestInfo": {
            "MachineName": "WEF"
        },
        "QueuedEvents": [
            {
                "EventID": "e68a21a6-8b8f-4834-a8f4-c51809a3b82d",
                "EventType": 101,
                "ConnectionID": "00000000-0000-0000-0000-000000000000",
                "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
                "Time": "2024-03-05T19:56:07.221262Z",
                "Host": "Cloud Account Administrator",
                "Data": "ping-google.bat"
            }
        ],
        "QueuedEventType": "QueuedElevatedTool",
        "QueuedEventHost": "Cloud Account Administrator",
        "QueuedEventData": "ping-google.bat",
	}
    "CorrelationEvent": null,
}
```




#### RanFiles
Unlike the `RanCommand` event, this event is triggered when a script file is set to be run by the Host machine, instead of when it is executed by the Guest machine. This means the event won't have the script's output, additionally the event does not include the script's contents to begin with.

```json
{
    "Event": {
        "EventID": "8c62739c-8dd6-4d44-ae90-0b6e9ea453f3",
        "EventType": "RanFiles",
        "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T19:24:24.9898043Z",
        "Host": "",
        "Data": "ping-google.bat"
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T19:24:19.7254004Z",
        "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
        "ProcessType": "Host",
        "ParticipantName": "Cloud Account Administrator",
        "NetworkAddress": "35.173.127.53",
    },
    "Session":{
	    "GuestNetworkAddress": "54.174.92.215",
	    "ActiveConnections": [
            {
                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
                "ProcessType": 2,
                "ParticipantName": "",
                "ClientType": 1,
                "NetworkAddress": "54.174.92.215",

            },
            {
                "ConnectedTime": "2024-03-05T19:24:19.7254004Z",
                "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
                "ProcessType": 1,
                "ParticipantName": "Cloud Account Administrator",
                "ClientType": 1,
                "NetworkAddress": "35.173.127.53"
            }
        ]
    }
    "CorrelationEvent": null
}
```


#### SentFiles
This event is triggered for bi-directional file transfers via the graphical file transfer tool provided by ConnectWise Control. The direction of the transfer is inferred by the "ProcessType" field within the "Connection" node. A value of "Guest" indicates the file is being transferred from the remote host to the local host, and a value of "Host" indicates that the file is being transferred from the local host to the remote agent. The exact file path is not included, only the filename.

<sub>A file is transferred from the local host to the remote agent.</sub>
```json
{
    "Event": {
        "EventID": "6325ba4e-0c3e-4c1a-b605-1f4ac253f489",
        "EventType": "SentFiles",
        "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T19:38:03.2222234Z",
        "Host": "",
        "Data": "DHQWebDAVDriveMappingTool.msi"
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T19:24:19.7254004Z",
        "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
        "ProcessType": "Host",
        "ParticipantName": "Cloud Account Administrator",
        "NetworkAddress": "35.173.127.53"
    },
    "Session": {
	    "GuestNetworkAddress": "54.174.92.215",
	    "ActiveConnections": [
            {
                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
                "ProcessType": 2,
                "ParticipantName": "",
                "ClientType": 1,
                "NetworkAddress": "54.174.92.215",
            },
            {
                "ConnectedTime": "2024-03-05T19:24:19.7254004Z",
                "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
                "ProcessType": 1,
                "ParticipantName": "Cloud Account Administrator",
                "ClientType": 1,
                "NetworkAddress": "35.173.127.53",
            }
        ]
    "CorrelationEvent": null
}
```

<sub>A file is transferred from the remote agent to the local host.</sub>
```json
{
    "Event": {
        "EventID": "180d5c0d-cd53-4114-868e-77457a680ac7",
        "EventType": "SentFiles",
        "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T21:36:19.9854197Z",
        "Host": "",
        "Data": "ScreenConnect.ClientSetup.msi"
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
        "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
        "ProcessType": "Guest",
        "ParticipantName": "",
        "NetworkAddress": "54.174.92.215"
    },
    "Session": {
        "GuestNetworkAddress": "54.174.92.215",
        "ActiveConnections": [
            {
                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
                "ProcessType": 2,
                "ParticipantName": "",
                "ClientType": 1,
                "NetworkAddress": "54.174.92.215"
            },
            {
                "ConnectedTime": "2024-03-05T21:36:03.5204796Z",
                "ConnectionID": "3d1d3590-81c5-4ce7-b767-792096993f0d",
                "ProcessType": 1,
                "ParticipantName": "Cloud Account Administrator",
                "ClientType": 1,
                "NetworkAddress": "35.173.127.53"
            }
        ]
    }
    "CorrelationEvent": null
}
```


#### SentMessage
This event is triggered by sending a message individually to a Guest machine.

```json
{
    "Event": {
        "EventID": "e1506b21-f3a7-43ec-aa19-2410af35d940",
        "EventType": "SentMessage",
        "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T19:39:42.4336393Z",
        "Host": "",
        "Data": "Hey there!"
    },
    "Connection": {
        "ConnectedTime": "2024-03-05T19:24:19.7254004Z",
        "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
        "ProcessType": "Host",
        "ParticipantName": "Cloud Account Administrator",
        "NetworkAddress": "35.173.127.53",
    },
        "ActiveConnections": [
            {
                "ConnectedTime": "2024-03-05T18:43:43.1330068Z",
                "ConnectionID": "28e368a7-0ca4-457a-9ed9-119d80f36a91",
                "ProcessType": 2,
                "ParticipantName": "",
                "NetworkAddress": "54.174.92.215",
            },
            {
                "ConnectedTime": "2024-03-05T19:24:19.7254004Z",
                "ConnectionID": "88b19c08-54b7-4577-8fb1-08485fc1de04",
                "ProcessType": 1,
                "ParticipantName": "Cloud Account Administrator",
                "NetworkAddress": "35.173.127.53",
            }
        ],
    },
    "CorrelationEvent": null,
}
```

#### QueuedMessage
It's also possible to send messages to multiple agents at once. Each agent receiving the message will generate a separate "QueuedMessage" event. To find out how many hosts a message was sent to one could count the number of unique hosts in the `Session.GuestInfo.MachineName` field by each message in the `Event.Data` field.

```json
{
    "Event": {
        "EventID": "63e6755e-a1ea-4796-b695-e02d18e599e7",
        "EventType": "QueuedMessage",
        "ConnectionID": "00000000-0000-0000-0000-000000000000",
        "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
        "Time": "2024-03-05T20:14:15.0944358Z",
        "Host": "Cloud Account Administrator",
        "Data": "Group Message, hello all!"
    },
    "Connection": null,
    "Session": {
        "GuestInfo": {
            "MachineName": "WEF",
        "QueuedEvents": [
            {
                "EventID": "63e6755e-a1ea-4796-b695-e02d18e599e7",
                "EventType": 45,
                "ConnectionID": "00000000-0000-0000-0000-000000000000",
                "CorrelationEventID": "00000000-0000-0000-0000-000000000000",
                "Time": "2024-03-05T20:14:15.0944358Z",
                "Host": "Cloud Account Administrator",
                "Data": "Group Message, hello all!"
            }
        ],
        "QueuedEventType": "QueuedMessage",
        "QueuedEventHost": "Cloud Account Administrator",
        "QueuedEventData": "Group Message, hello all!",
    "CorrelationEvent": null
}
```

## Useful notes

If you see https://<subdomain>.screenconnect.com, this is the username of the account.^[4]^ ^[5]^

## References
[^1]: [Remote Access Software - Forensics](https://vikas-singh.notion.site/vikas-singh/Remote-Access-Software-Forensics-3e38d9a66ca0414ca9c882ad67f4f71b)
[^2]: [Establishing Connections: Illuminating Remote Access Artifacts in Windows](https://youtu.be/0qSWfbti4yM?list=PLfouvuAjspToNFRwt0ssrvaSMI11RcSgp)
[^3]: [Analysis on legit tools abused in human operated ransomware](https://jsac.jpcert.or.jp/archive/2023/pdf/JSAC2023_1_1_yamashige-nakatani-tanaka_en.pdf)
[^4]: [RMM – ScreenConnect: Client-Side Evidence](https://dfirtnt.wordpress.com/2023/07/14/rmm-screenconnect-client-side-evidence/)
[^5]: [Configure ConnectWise Control for Single Sign-On](https://docs.citrix.com/en-us/citrix-secure-private-access/downloads/connect-wise-control.pdf)
[^6]: [Session Manager API reference Enumerations Updated](https://docs.connectwise.com/ConnectWise_ScreenConnect_Documentation/Developers/Session_Manager_API_Reference/Enumerations)
[^7]:[Session Manager API reference Enumerations Old](https://docs.connectwise.com/ConnectWise_ScreenConnect_Media_Repo/Control_developer_docs_mockup/Session_Manager_API_Reference/Enumerations)
