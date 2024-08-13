import { spec } from  "node:test/reporters";
import process from 'node:process';
import { run } from "node:test";
import { globSync } from "glob";

run({
	files: globSync("test/**/*.test.mts").sort((a, b) => String.prototype.localeCompare.call(a, b)),
	concurrency: false,
})
.on('test:fail', () => { process.exitCode = 1; })
.compose(new spec())
.pipe(process.stdout);
