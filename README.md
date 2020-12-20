# About

This library implements an experimental Golang shim for gRPC that implements privacy guarantees for users of gRPC and protocol buffers. Specifically, it enables developers to enforce rules against data access within or between microservices for messages sent along the wire.

A full explanation can be seen in our [report](https://github.com/CSCI-2390-Project/privacy-go/blob/main/CS2390_Project_Final_Report.pdf)

An example application here for build + run: https://github.com/CSCI-2390-Project/privacy-example

If you wish to build and play with the full ten-microservice application we benchmarked against with our changes, kindly start a Kubernetes cluster (either locally with `kind` or other) and run `skaffold run` while in the `master` branch of [this repository](https://github.com/CSCI-2390-Project/microservices-demo). 
