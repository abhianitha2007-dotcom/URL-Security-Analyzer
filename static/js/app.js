(() => {
    const overlay = document.querySelector("[data-scan-overlay]");
    document.querySelectorAll("[data-scan-form]").forEach((form) => {
        form.addEventListener("submit", () => {
            if (form.checkValidity() && overlay) {
                overlay.hidden = false;
                document.body.classList.add("is-scanning");
            }
        });
    });

    document.querySelectorAll("form[data-confirm]").forEach((form) => {
        form.addEventListener("submit", (event) => {
            if (!window.confirm(form.dataset.confirm)) event.preventDefault();
        });
    });

    const search = document.querySelector("[data-history-search]");
    const rows = [...document.querySelectorAll("[data-history-row]")];
    const empty = document.querySelector("[data-history-empty]");
    if (search && rows.length) {
        search.addEventListener("input", () => {
            const query = search.value.trim().toLowerCase();
            let visible = 0;
            rows.forEach((row) => {
                const match = row.dataset.search.includes(query);
                row.hidden = !match;
                if (match) visible += 1;
            });
            if (empty) empty.hidden = visible !== 0;
        });
    }
})();
