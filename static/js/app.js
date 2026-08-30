(() => {
    const root = document.documentElement;
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    root.classList.add("motion-ready");

    const warningGate = document.querySelector("[data-warning-gate]");
    const warningDismiss = document.querySelector("[data-warning-dismiss]");
    if (warningGate && warningDismiss) {
        warningDismiss.focus();
        warningDismiss.addEventListener("click", () => {
            warningGate.hidden = true;
            document.body.classList.remove("warning-pending");
            document.querySelector(".report-nav a, .report-footer-actions a")?.focus();
        });
    }

    const overlay = document.querySelector("[data-scan-overlay]");
    const scanTitle = document.querySelector("[data-scan-title]");
    const scanMessage = document.querySelector("[data-scan-message]");
    const scanProgress = document.querySelector("[data-scan-progress]");
    const scanIndicators = [...document.querySelectorAll("[data-scan-stage]")];
    const scanStages = [
        ["Validating public destination", "Confirming DNS and blocking private or unsafe network targets.", 16],
        ["Capturing stable evidence", "Following safe redirects and freezing one immutable page snapshot.", 38],
        ["Correlating security layers", "Checking structure, domain identity, behavior, posture, and reputation.", 68],
        ["Building complete report", "Verifying every required result before calculating the final score.", 92],
    ];

    const showScanStage = (index) => {
        const [title, message, progress] = scanStages[index];
        if (scanTitle) scanTitle.textContent = title;
        if (scanMessage) scanMessage.textContent = message;
        if (scanProgress) scanProgress.style.width = `${progress}%`;
        scanIndicators.forEach((indicator, position) => {
            indicator.classList.toggle("is-active", position === index);
            indicator.classList.toggle("is-complete", position < index);
        });
    };

    document.querySelectorAll("[data-scan-form]").forEach((form) => {
        form.addEventListener("submit", () => {
            if (!form.checkValidity() || !overlay) return;
            overlay.hidden = false;
            document.body.classList.add("is-scanning");
            let stage = 0;
            showScanStage(stage);
            const advanceStage = () => {
                if (stage >= scanStages.length - 1) return;
                showScanStage(++stage);
                window.setTimeout(advanceStage, 3200);
            };
            window.setTimeout(advanceStage, 3200);
        });
    });

    window.addEventListener("pageshow", (event) => {
        if (!event.persisted || !overlay) return;
        overlay.hidden = true;
        document.body.classList.remove("is-scanning");
    });

    const controls = document.querySelectorAll(
        ".button, .input-combo button, .icon-button, .nav-link, .report-nav a"
    );
    controls.forEach((control) => {
        control.classList.add("interactive-control");
        control.addEventListener("pointerdown", (event) => {
            const rect = control.getBoundingClientRect();
            control.style.setProperty("--press-x", `${event.clientX - rect.left}px`);
            control.style.setProperty("--press-y", `${event.clientY - rect.top}px`);
            control.classList.remove("is-pressed");
            window.requestAnimationFrame(() => control.classList.add("is-pressed"));
            window.setTimeout(() => control.classList.remove("is-pressed"), 520);
        });
    });

    if (!reducedMotion && window.matchMedia("(pointer: fine)").matches) {
        let pointerFrame = 0;
        document.addEventListener("pointermove", (event) => {
            if (pointerFrame) return;
            pointerFrame = window.requestAnimationFrame(() => {
                const x = event.clientX / window.innerWidth - 0.5;
                const y = event.clientY / window.innerHeight - 0.5;
                root.style.setProperty("--pointer-x", `${event.clientX}px`);
                root.style.setProperty("--pointer-y", `${event.clientY}px`);
                root.style.setProperty("--parallax-x", `${x * 30}px`);
                root.style.setProperty("--parallax-y", `${y * 24}px`);
                pointerFrame = 0;
            });
        });

        document.querySelectorAll("[data-tilt]").forEach((element) => {
            element.addEventListener("pointermove", (event) => {
                const rect = element.getBoundingClientRect();
                const x = (event.clientX - rect.left) / rect.width - 0.5;
                const y = (event.clientY - rect.top) / rect.height - 0.5;
                element.style.setProperty("--tilt-x", `${y * -4}deg`);
                element.style.setProperty("--tilt-y", `${x * 5}deg`);
                element.style.setProperty("--glare-x", `${(x + 0.5) * 100}%`);
                element.style.setProperty("--glare-y", `${(y + 0.5) * 100}%`);
            });
            element.addEventListener("pointerleave", () => {
                element.style.setProperty("--tilt-x", "0deg");
                element.style.setProperty("--tilt-y", "0deg");
            });
        });
    }

    const revealTargets = document.querySelectorAll(
        ".section-heading, .trust-strip span, .method-grid > div, " +
        ".assessment-card, .content-alert, .report-panel, .side-panel, " +
        ".metric-grid article, .history-row, .state-card"
    );
    revealTargets.forEach((element) => element.setAttribute("data-reveal", ""));
    if (reducedMotion || !("IntersectionObserver" in window)) {
        revealTargets.forEach((element) => element.classList.add("is-visible"));
    } else {
        const revealObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) return;
                entry.target.classList.add("is-visible");
                observer.unobserve(entry.target);
            });
        }, { threshold: 0.12 });
        revealTargets.forEach((element) => revealObserver.observe(element));
    }

    const animateCounter = (element) => {
        if (element.dataset.counted) return;
        element.dataset.counted = "true";
        const original = element.textContent.trim();
        const target = Number(original);
        if (!Number.isFinite(target) || reducedMotion) return;
        const decimals = original.includes(".") ? original.split(".")[1].length : 0;
        const started = performance.now();
        const duration = 850;
        const draw = (now) => {
            const progress = Math.min((now - started) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3);
            element.textContent = (target * eased).toFixed(decimals);
            if (progress < 1) window.requestAnimationFrame(draw);
            else element.textContent = original;
        };
        element.textContent = (0).toFixed(decimals);
        window.requestAnimationFrame(draw);
    };

    const counters = document.querySelectorAll("[data-counter]");
    if ("IntersectionObserver" in window && !reducedMotion) {
        const counterObserver = new IntersectionObserver((entries, observer) => {
            entries.forEach((entry) => {
                if (!entry.isIntersecting) return;
                animateCounter(entry.target);
                observer.unobserve(entry.target);
            });
        }, { threshold: 0.6 });
        counters.forEach((counter) => counterObserver.observe(counter));
    } else {
        counters.forEach(animateCounter);
    }

    const reportLinks = [...document.querySelectorAll('.report-nav a[href^="#"]')];
    const reportSections = reportLinks
        .map((link) => document.querySelector(link.getAttribute("href")))
        .filter(Boolean);
    if (reportLinks.length) reportLinks[0].classList.add("is-active");
    if (reportSections.length && "IntersectionObserver" in window) {
        const sectionObserver = new IntersectionObserver((entries) => {
            const visible = entries.find((entry) => entry.isIntersecting);
            if (!visible) return;
            reportLinks.forEach((link) => {
                link.classList.toggle(
                    "is-active",
                    link.getAttribute("href") === `#${visible.target.id}`
                );
            });
        }, { rootMargin: "-20% 0px -68%", threshold: 0 });
        reportSections.forEach((section) => sectionObserver.observe(section));
    }

    const pageProgress = document.querySelector("[data-page-progress]");
    let scrollFrame = 0;
    const updateScroll = () => {
        if (scrollFrame) return;
        scrollFrame = window.requestAnimationFrame(() => {
            const maximum = document.documentElement.scrollHeight - window.innerHeight;
            const progress = maximum > 0 ? Math.min(window.scrollY / maximum, 1) : 0;
            if (pageProgress) pageProgress.style.transform = `scaleX(${progress})`;
            document.body.classList.toggle("has-scrolled", window.scrollY > 12);
            scrollFrame = 0;
        });
    };
    updateScroll();
    window.addEventListener("scroll", updateScroll, { passive: true });

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
