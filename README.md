LHFX – Linux–Hadoop Forensics Extractor

A NameNode-centric digital forensic support tool for Linux-Hadoop Big-Data environments.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Overview:



The Linux–Hadoop Forensics Extractor (LHFX) is a specialised forensic Python-based triage utility designed to bridge the gap between distributed Big-Data storage architectures and actionable forensic intelligence.



Hadoop environments distribute data, services, and configuration across multiple DataNodes and containerised Linux layers, creating significant forensic complexity. However, the NameNode centralises metadata describing this distribution—maintaining filesystem namespace, node mappings, replication state, and cluster configuration. For this reason, an investigator typically acquires a forensic image of the NameNode to obtain global visibility of the distributed system.



Traditional forensic suites can still struggle in this context, often requiring extensive indexing of large NameNode images without efficiently reconstructing cluster structure or storage relationships. LHFX addresses this challenge by acting as a highly targeted, forensically sound triage “kickstart.” Rather than exhaustively indexing all stored data, LHFX programmatically hunts for high-signal forensic “beacons,” automatically identifying, hashing, and extracting artefacts across both Linux OS and Hadoop layers, collecting critical system evidence (e.g., authentication logs, container metadata, etc.) alongside Hadoop metadata and configuration (e.g., fsimage, edits, XML files) in minutes.



Operating in a strictly read-only, NPCC/ISO-aligned workflow, LHFX organises extracted intelligence into a structured Evidence\_Vault accompanied by a machine-readable manifest (manifest.jsonl) and a human-readable Executive\_Summary.md. This enables investigators to rapidly reconstruct cluster topology, understand distributed storage context, assess configuration and security state, and identify anomalous user or system activity before committing to deeper analysis with conventional forensic platforms.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Why Hadoop Big-Data Environments Are Forensically Challenging.



Digital forensic analysis in Hadoop environments is difficult due to several inherent characteristics:

•	Distributed storage – data is spread across many DataNodes

•	Centralised metadata – file structure exists primarily on the NameNode

•	Complex configuration layers – XML-based cluster configuration

•	Multiple ecosystem services – e.g., Spark, Hive, HBase, ZooKeeper

•	Containerisation and virtualisation – Docker/overlay storage layers

•	Scale – very large datasets and logs

•	Heterogeneous deployments – varied distributions and layouts

Traditional forensic tools operate mainly at filesystem level and struggle to interpret Hadoop-specific metadata or cluster topology. Investigators must therefore first understand how the distributed system is structured before meaningful evidence analysis can occur. LHFX automates this orientation stage.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Why Linux–Hadoop Environments Were Chosen.

Linux-based Hadoop clusters represent a realistic and forensically significant class of modern enterprise systems because they are widely used for:

•	Healthcare big-data platforms

•	Financial analytics systems

•	Cloud storage backends

•	Distributed processing infrastructures

These environments combine:

•	Linux operating systems

•	Distributed storage architecture

•	Specialised metadata structures

•	layered services and containers

They therefore present a representative and technically challenging digital forensic scenario, motivating the development of LHFX as part of research into digital forensics readiness in big-data environments.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Hadoop Architecture Context.

A Hadoop storage cluster (HDFS) consists of:

•	NameNode – central metadata controller

•	DataNodes (DN₁…DNₙ) – distributed data storage nodes

Among its primary operational and security responsibilities, the NameNode maintains:

•	Filesystem namespace

•	File-to-DataNode mapping

•	Replication state

•	Cluster topology

•	Transaction history

It is therefore analogous to a global filesystem index for the entire cluster.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Why LHFX Focuses on NameNode Images.

Imaging every node in a large Hadoop cluster is often impractical due to:

•	Cluster size

•	Distributed storage volume

•	Operational constraints

However, the NameNode contains the highest evidential value for reconstructing the distributed system because it stores metadata describing all DataNodes and file locations.

A forensic image of the NameNode can therefore reveal:

•	Where data existed in the cluster

•	How it was organised

•	Which nodes stored it

•	How the system was configured

LHFX adopts this realistic forensic assumption and is specifically designed for NameNode-centric analysis.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

What LHFX Extracts.

LHFX does not attempt full data acquisition.

Instead, it extracts supporting evidential artefacts that orient the investigator within the distributed system.

Supporting evidence includes:



Linux operating system artefacts:

* &nbsp;	User and privilege data: Account configurations and password hashes (passwd, group, shadow) alongside privilege escalation rules (sudoers).
* &nbsp;	Host and network configuration: System identity and local routing details (hostname, hosts, OS-release, lsb-release).
* &nbsp;	Filesystem and remote access: Disk mounting rules (fstab), scheduled tasks (crontab), and SSH daemon configurations (sshd\_config).
* &nbsp;	System and authentication logs: Comprehensive auditing trails capturing logins, package changes, and kernel events (auth.log, secure, syslog, messages, kern.log, boot.log, wtmp, 	btmp, lastlog).

Hadoop metadata artefacts:

* &nbsp;	Namespace state files: Point-in-time snapshots of the entire filesystem structure (fsimage\_, fsimage.ckpt\_).
* &nbsp;	Filesystem transaction logs: The ongoing, incremental records of every file modification (edits\_, edits\_inprogress\_).
* &nbsp;	State and transaction indicators: Core operational anchors (VERSION, seen\_txid, fstime, in\_use.lock).

Cluster configuration artefacts

• 	core-site.xml, hdfs-site.xml, yarn-site.xml

• 	Node lists and topology

• 	Replication and storage parameters

Ecosystem and container artefacts

• 	ZooKeeper, Spark, Hive, HBase, Kafka, Oozie, Flume, Sqoop, and Ranger configuration

•  	Container storage metadata (Docker/overlay2)

These artefacts collectively allow reconstruction of the distributed storage environment from a single NameNode image.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Role in Digital Forensic Investigations.

LHFX is a forensic orientation and supporting-evidence extraction tool.

It supports early investigative stages:

•	Identification

•	System understanding

•	Configuration reconstruction

•	Storage mapping

It does not replace full forensic analysis tools.

Instead, it prepares investigators to use them effectively.

Position in workflow:

1\.	Acquire NameNode forensic image

2\.	Run LHFX → reconstruct cluster context

3\.	Identify relevant nodes/data paths

4\.	Perform deep forensic analysis

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

How LHFX Solves the Big-Data Forensic Challenge.

LHFX addresses Hadoop forensic complexity by:

•	Locating known forensic “beacons”

•	Parsing configuration automatically

•	Reconstructing cluster topology

•	Identifying ecosystem services

•	Detecting containerised storage

•	Organising artefacts by role

•	Generating structured reports

This reduces investigative time and cognitive load in distributed environments.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Digital Forensic Principles Compliance.

LHFX is designed to maintain forensic soundness:

•	Operates on forensic disk images

•	Read-only mounting (ro, noload / norecovery)

•	Optional cryptographic hashing

•	No modification of the evidence source

•	Full command logging

•	Manifest of extracted artefacts

•	Repeatable workflow

Outputs support verification and admissibility.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Investigator Workflow.

LHFX provides a guided GUI workflow:

1\.	Select NameNode forensic image or mounted root

2\.	Optional integrity hashing

3\.	Select output directory

4\.	Configure scan options

5\.	Run automated extraction

The tool then:

•	Mounts the image read-only

* Verifies image integrity

•	Discovers artefacts

•	Extracts supporting evidence

•	logs actions

•	Generates reports

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Outputs.

LHFX produces structured forensic outputs:

•	Evidence\_Vault/ – categorised artefacts

•	Executive\_Summary.md – human-readable overview

•	manifest.jsonl – extraction log with hashes

•	report.json – structured metadata

•	logs/tool.log – audit trail

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Intended Users.

LHFX is designed for:

•	Digital forensic investigators

•	Cybersecurity analysts

•	Incident responders

•	Researchers

No prior Hadoop expertise is required after initial execution.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Research Context:

LHFX was developed as part of doctoral research detailed in the thesis, *"Implementation of Digital Forensics Readiness in Big Data Wireless Medical Networks"*. The tool operationalises theoretical forensic readiness principles by providing a practical, defensible artefact-extraction mechanism for Linux-Hadoop big data distributed systems.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

Summary:

LHFX is a NameNode-centric digital forensic support tool that enables investigators to reconstruct Linux-Hadoop distributed storage environments from a single forensic image by extracting and organising high-value supporting artefacts.

It bridges the gap between traditional filesystem-level forensic tools and modern distributed Big-Data architectures.

\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_\_

