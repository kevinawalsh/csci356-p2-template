
if (document.readyState == 'complete') {
    initialize_chat();
} else {
    document.onreadystatechange = function() {
      if (document.readyState === 'complete')
        initialize_chat();
    };
}

function initialize_chat() {
    document.getElementById("chatmsg").addEventListener("keyup",
        function(event) {
            if (event.key === "Enter")
                send_chat();
            return false;
        });
    join_room(null);
    update_room_list();
}

var roomVersion = -1;
var roomCount = 0;

function update_room_list() {
    console.log("update room list");
    // Get list of rooms from server by making an HTTP request for /chat/roomlist
    var req = new XMLHttpRequest();
    req.open("GET", "/chat/roomlist?version="+(roomVersion+1));
    console.log("sending HTTP GET for roomlist");
    req.send();
    req.onerror = () => {
        clear_room_list("HTTP GET for roomlist seems to have failed...");
        roomVersion = -1;
        setTimeout(update_room_list, 5000);
    };
    req.onload = (event) => {
        // The HTTP request is done
        console.log("finished HTTP GET for roomlist");
        if (req.status != 200) {
            clear_room_list("HTTP GET for roomlist finished, but with status " + req.status);
            setTimeout(update_room_list, 5000);
            return;
        }

        // The response should be a version number and a list of rooms, one per line
        var rooms = req.response.trim().split("\n");
        var newVersion = Number(rooms.shift());
        if (newVersion <= roomVersion) {
            alert("Oops, we asked for newer than version "+roomVersion+" of room list, but server gave us version " + newVersion);
            setTimeout(update_room_list, 5000);
            return;
        }
        roomVersion = newVersion
 
        // Populate the HTML list with the room names
        var l = document.getElementById("roomlist");
        var p = document.getElementById("placeholder");

        clear_room_list("Updating room list...");
        roomCount = rooms.length;
        if (roomCount == 0)
            p.innerHTML = "No rooms have been created yet...";
        else
            p.innerHTML = "There are " + roomCount + " chat rooms available!";

        var found_room = false;
        for (var i = 0; i < rooms.length; i++) {
            var name = rooms[i].trim();
            var button = document.createElement("div");
            button.classList.add("room_button");
            button.id = "room_" + name;
            button.innerHTML = "<i>" + name + "</i>";
            button.onclick = ((name) => () => join_room(name))(name);
            if (name == selected_room) {
                button.classList.add("selected_room");
                found_room = true;
            }
            l.insertBefore(button, p);
        }
        if (selected_room != null && !found_room) {
            join_room(null);
        }
        setTimeout(update_room_list, 0);
    };
}

function clear_room_list(msg) {
    console.log("clearing room list");
    // Clear the HTML list of all room names
    var buttons = document.getElementsByClassName("room_button");
    while (buttons.length > 0) {
        var b = buttons[0];
        b.parentNode.removeChild(b);
    }
    var p = document.getElementById("placeholder");
    p.innerHTML = msg;
}

function send_chat() {
    var m = document.getElementById("chatmsg");
    var msg = m.value;
    console.log("send chat '" + msg +"' to room '"+selected_room+"'");
    if (selected_room == null)
        return;
    m.value = "";
    // Send new chat message to server by making an HTTP POST to /chat/room/name
    var req = new XMLHttpRequest();
    req.open("POST", "/chat/room/"+encodeURIComponent(selected_room)+"?message="+encodeURIComponent(msg));
    console.log("sending HTTP GET for chat room contents");
    req.send();
    req.onerror = () => { alert("HTTP POST to chat room seems to have failed..."); };
    req.onload = (event) => {
        // The HTTP request is done
        console.log("finished HTTP POST to chat room contents");
        if (req.status != 200) {
            alert("HTTP POST to chat room contents finished, but with status " + req.status);
            return;
        }
        // Response should be "success" or an error message
        var resp = req.response.trim();
        if (resp != "success") {
            alert("Sorry, server says: " + resp);
            return;
        }
    };
    return false;
}

function create_room() {
    console.log("create room");
    var name = prompt("Please pick a name for the new room", "Alices's Restaurant").trim();
    if (name == null || name == "")
      return;
    // Perform HTTP POST to create the new room
    // var formData = new FormData();
    // formData.append("name", name);
    var req = new XMLHttpRequest();
    req.open("POST", "/chat/createroom");
    // req.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
    req.setRequestHeader("Content-type", "text/plain");
    req.send("name="+name);
    req.onerror = () => { alert("Sorry, something went wrong creating the room."); }
    req.onload = (event) => {
        // The HTTP request is done
        console.log("finished HTTP POST for createroom");
        if (req.status != 200) {
            alert("HTTP POST for createroom finished, but with status " + req.status);
            return;
        }

        // Response should be "success" or an error message
        var resp = req.response.trim();
        if (resp != "success") {
            alert("Sorry, server says: " + resp);
            return;
        }

        /*
        // Add the new room to the HTML list
        var l = document.getElementById("roomlist");
        var p = document.getElementById("placeholder");
          
        roomCount++;
        p.innerHTML = "There are now " + roomCount + " chat rooms available!";

        var d = document.createElement("div");
        d.classList.add("room_button");
        d.innerHTML = "Join <i>" + name + "</i>";
        d.onclick = ((name) => () => join_room(name))(name);
        l.insertBefore(d, p);
        */
    };

    return false;
}

var chat_version = -1;
var selected_room = null;
var chat_request = null;

function join_room(name) {
    console.log("join room: '" + name + "'");
    document.getElementById("sendmsg").disabled = (name == null);
    var buttons = document.getElementsByClassName("room_button");
    for (var i = 0; i < buttons.length; i++) {
        var button = buttons[i];
        if (button.id == "room_" + name)
            button.classList.add("selected_room");
        else
            button.classList.remove("selected_room");
    }
    chat_version = -1;
    selected_room = name;
    update_chat_box();
}

function update_chat_box() {
    // cancel any outstanding requests
    if (chat_request != null) {
        chat_request.abort();
        chat_request = null;
    }
    console.log("update chat box");
    var box = document.getElementById("chatroom");
    if (selected_room == null) {
        box.value = "[You are not in any room]\n";
        return;
    }
    
    // Get chat contents from server by making an HTTP request for /chat/room/name
    var req = new XMLHttpRequest();
    req.open("GET", "/chat/room/"+encodeURIComponent(selected_room)+"?version="+(chat_version+1));
    console.log("sending HTTP GET for chat room contents");
    req.send();
    chat_request = req;
    req.onerror = () => {
        clear_chat_box("HTTP GET for chat room contents seems to have failed...");
        chat_version = -1;
        setTimeout(update_chat_box, 5000);
    };
    req.onload = (event) => {
        // The HTTP request is done
        console.log("finished HTTP GET for chat room contents");
        if (req.status != 200) {
            clear_chat_box("HTTP GET for chat room contents finished, but with status " + req.status);
            setTimeout(update_chat_box, 5000);
            return;
        }

        // The response should be a version number on one line, then the contents of the room
        var resp = req.response;
        var i = resp.indexOf('\n');
        var newVersion = Number(resp.slice(0, i));
        var body = resp.slice(i+1);
        // if (newVersion <= chat_version) {
        //     alert("Oops, we asked for newer than version "+roomVersion+" of room list, but server gave us version " + newVersion);
        //     setTimeout(update_chat_box, 5000);
        //     return;
        // }
        chat_version = newVersion
        box.value = "[You have entered " + selected_room +"]\n" + body;
 
        setTimeout(update_chat_box, 0);
    };
}
