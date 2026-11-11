#!/usr/bin/env node
"use strict";

require("../lib/binary").spawnBinary("basalt", process.argv.slice(2));
