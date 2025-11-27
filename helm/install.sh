#!/bin/bash
helm upgrade --install otter-wiki  . --values ./values.yaml --values ./values-prod.yaml
