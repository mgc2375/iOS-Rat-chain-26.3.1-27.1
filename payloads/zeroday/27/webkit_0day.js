// TODO: fresh WebKit 0day for {arch}.
// Requirements vs CVE-2026-43715: bypass KTRR, KPP, and JIT sandbox.
// Typical recipe: stable arbitrary-read (leak kernel slide) ->
// arbitrary-write (patch task_map / amfi) -> callback.
(function () {
  "use strict";
  window.onExploit = function () { console.log("webkit 0day"); };
})();