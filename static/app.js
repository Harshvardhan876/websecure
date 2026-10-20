// Small progressive enhancements shared by every page. Each page still works without this file.
(function () {
    var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

    // Count numbers up from 0. The final value is already in the HTML.
    if (!reduceMotion) {
        document.querySelectorAll("[data-count]").forEach(function (el) {
            var target = Number(el.dataset.count);
            var start = performance.now();
            el.textContent = "0";
            (function tick(now) {
                var t = Math.min((now - start) / 900, 1);
                el.textContent = Math.round(target * (1 - Math.pow(1 - t, 3)));
                if (t < 1) requestAnimationFrame(tick);
            })(start);
        });
    }

    // Gauges, rings and bars animate from empty to their value once this class lands.
    requestAnimationFrame(function () {
        requestAnimationFrame(function () { document.body.classList.add("is-ready"); });
    });

    // Notifications: close button, and they hide themselves after a few seconds.
    document.querySelectorAll(".toast").forEach(function (toast) {
        function hide() {
            toast.classList.add("is-leaving");
            setTimeout(function () { toast.remove(); }, 250);
        }
        toast.querySelector("button").addEventListener("click", hide);
        setTimeout(hide, 5000);
    });

    // Copy buttons: <button data-copy="text">
    document.querySelectorAll("[data-copy]").forEach(function (button) {
        button.addEventListener("click", function () {
            if (!navigator.clipboard) return;
            navigator.clipboard.writeText(button.dataset.copy).then(function () {
                var label = button.textContent;
                button.textContent = "Copied";
                button.classList.add("is-done");
                setTimeout(function () { button.textContent = label; button.classList.remove("is-done"); }, 1500);
            });
        });
    });

    // Filterable lists. Rows carry data-filter-value and optionally data-search; controls point at the list
    // with data-filter-for (chip buttons) and data-search-for (text input); data-empty-for shows when nothing matches.
    function applyFilters(listId) {
        var list = document.getElementById(listId);
        var chip = document.querySelector('[data-filter-for="' + listId + '"] [aria-pressed="true"]');
        var search = document.querySelector('[data-search-for="' + listId + '"]');
        var wanted = chip ? chip.dataset.filter : "all";
        var query = search ? search.value.trim().toLowerCase() : "";
        var shown = 0;
        list.querySelectorAll("[data-filter-value]").forEach(function (row) {
            var visible = (wanted === "all" || row.dataset.filterValue === wanted) &&
                (!query || (row.dataset.search || "").indexOf(query) !== -1);
            row.hidden = !visible;
            if (visible) shown += 1;
        });
        var empty = document.querySelector('[data-empty-for="' + listId + '"]');
        if (empty) empty.hidden = shown > 0;
    }
    document.querySelectorAll("[data-filter-for]").forEach(function (group) {
        group.querySelectorAll("button").forEach(function (button) {
            button.addEventListener("click", function () {
                group.querySelectorAll("button").forEach(function (b) { b.setAttribute("aria-pressed", String(b === button)); });
                applyFilters(group.dataset.filterFor);
            });
        });
    });
    document.querySelectorAll("[data-search-for]").forEach(function (input) {
        input.addEventListener("input", function () { applyFilters(input.dataset.searchFor); });
    });

    // Tabs: buttons with data-tab="<panel id>" inside [data-tabs]; one panel visible at a time.
    document.querySelectorAll("[data-tabs]").forEach(function (list) {
        var tabs = list.querySelectorAll("[data-tab]");
        tabs.forEach(function (tab) {
            tab.addEventListener("click", function () {
                tabs.forEach(function (t) {
                    var selected = t === tab;
                    t.setAttribute("aria-selected", String(selected));
                    document.getElementById(t.dataset.tab).hidden = !selected;
                });
            });
        });
    });

    // Show / hide password
    document.querySelectorAll("[data-toggle-password]").forEach(function (button) {
        button.addEventListener("click", function () {
            var input = document.getElementById(button.dataset.togglePassword);
            var show = input.type === "password";
            input.type = show ? "text" : "password";
            button.textContent = show ? "Hide" : "Show";
            button.setAttribute("aria-pressed", String(show));
            button.setAttribute("aria-label", show ? "Hide password" : "Show password");
        });
    });

    // Forms with data-busy="Scanning" show progress on their submit button and cannot be sent twice.
    document.querySelectorAll("form[data-busy]").forEach(function (form) {
        form.addEventListener("submit", function () {
            var button = form.querySelector("button[type=submit]");
            if (button) {
                button.disabled = true;
                button.textContent = form.dataset.busy;
            }
        });
    });
})();
