# P2P File Sharing System Based on Chord 🗂️

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Introduction

> This is a project for the course CSEN317 Distributed System @Santa Clara University.

This repository contains the code for a file sharing system, designed to manage and facilitate the sharing of course-related files. 

![image-20240205131925188](https://i.imgur.com/yT5zqnx.png)

### Backend

The system is implemented using Flask and handles file uploads, queries, and other operations.

### Frontend

There is also a web interface developed for this application, for the latest code, please refer to [this repository](https://github.com/ha0min/filesharingweb).

### Demo

A demo video could be found [here](https://webpages.scu.edu/ftp/hcheng5/317demo.webm). The video has no audio. 

For presentation video, please kindly review the link submitted via camino.

## Features 🌟

- 📤 **File Upload and Storage Management**: Handle the uploading and storage of files securely.
- 🔍 **Query System**: Locate and retrieve files efficiently.
- 👨‍🏫 **Leader Election**: Server would elect a leader to handle join and leave operations from chord.
- 📁 **Resource Discovery**: Server would join the chord and handle the operations from chord.
- 📝 **Replication & Consistency**: Node would replicate files and ensure consistency.

---

## Getting Started 🚀

These instructions will get you a copy of the project up and running on your local machine for development and testing
purposes.

### Prerequisites 📋{#prerequisites}

#### Before you begin

Ensure your machine is publicly accessible via ip. 

Otherwise, you should run all the nodes including server in the same network.

If you don't wanna set up AWS bucket for leader election, see instructions under [using local mode](#using-local-mode).

##### 1. Add `.env` file to the root directory of the project.

The file should contain the following environment variables:

   ```bash
AWS_ACCESS_KEY=
AWS_SECRET_KEY=
REGION_NAME=
   ```

The AWS credentials should have access to S3 and could perform all operations on S3, including delete object.

##### 2. Change variables.

Add the two bucket in your S3 instance. 

Then update `BUCKET_NAME` and `SERVER_BUCKET_NAME`  in `supernode.py` to your own bucket name.

### Installation 🔧

1. Clone the repository:

   ```bash
   git clone https://github.com/ha0min/filesharing.git
   ```

2. Install dependencies:

   ```bash
    pip install -r requirements.txt
   ```

3. (Optional) Install dependencies for the frontend:

   ```bash
    cd filesharingweb
    yarn install
   ```

---

## Usage 💡

There is two types of nodes in the system: **supernode(server)** and **normal node**.

Normal node could only initiate when there is a supernode running.

### Using Local Mode{#using-local-mode}

If you don't wanna set up AWS for leader config, try local mode; otherwise, confirm you finished [setup](#prerequisites).

Under `config.py`, set the `LOCAL_SERVER` to `true`.

### Start a supernode

```bash
python3 flask_server.py -p port_number -b true -k replication_factor
```

A flask server should be running on the `port_number` of your machine's ip. 

Visiting the ip and port number should give you the info stored in that node.

### Start a normal node

```bash
python3 flask_server.py -p port_number
```

A flask server should be running on the `port_number` of your machine's ip. 

The node should get the info supernode and ask to join the chord.

Visiting the ip and port number should give you the info stored in that node.

### Start a web interface

```bash
cd filesharingweb
yarn start
```

A web interface should be running on `localhost:3000`.

---

## Development 🛠️

### Code Structure 📚

A file tree of the project is:

```
.
├── README.md                
├── chord.py                  # Module for normal node
├── config.py                 # Configuration settings and parameters for the application
├── filesharingweb            # React/Next.js frontend application submodule
├── flask_server.py           # Main entry point for the backend application
├── requirements.txt          
├── supernode.py              # Module for supernode functionalities in the system
└── utils                     
    ├── colorfy.py            # Utility for colorizing terminal output
    ├── common.py             # Global constants and variables
    ├── endpoints.py          # Definitions of API endpoints
    └── util.py               # General utility functions
```

## Testcases

I tried to take care of all the corner case that might happened for a distributed system, but some issues might persisted; if so, welcome to bring up an issue under [here](https://github.com/ha0min/filesharing/issues).

#### Super Node

Some cases that only related to the part of super node have been tested and passed:

1. When AWS file is not found, super node would not start.
2. When there is only one super node, the node automatically elected as the leader.
3. When the only super node goes down, the whole network is down.

We also support heartbeat:

1. When there is a leader and one super node join, the newly joined node would sent heartbeat request to leader during a period of time.
2. When the leader is dead, it will try to initiate a new leader election.

#### Normal Node

Some cases that only related to the part of normal node have been tested and passed:

1. When user upload a file, the file would be stored by the responsible node in the chord.
2. When user query a file, the file can be retrieved from the responsible node in the chord.
3. When the new node join, the files would redistribute.
4. When the node leave the network, the legacy files would transfer to the neighbors.

Some cases happened when the replication is enabled:

1. When the file should hosted by a node, but there is no file in its directory, the node would ask for its successors in the chord for replica and then host it.

#### Super Node and Normal Node

1. When the super node is down, the normal node could not join the network.
2. When the replication is possible, that is number of node is greater than the  replication factor (set when starting the super node), the replication would started.
3. When the new leader is elected, the nodes' join and leave operations would reported to the new leader.

## License 📄

[MIT](https://choosealicense.com/licenses/mit/)

