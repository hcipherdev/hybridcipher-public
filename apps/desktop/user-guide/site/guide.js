// Walkthrough player: builds its slides from the step figures, so each screenshot and
// subtitle is written once.
(function () {
    const figures = Array.from(document.querySelectorAll('figure[data-slide]'));
    const screen = document.getElementById('playerScreen');
    const subtitle = document.getElementById('playerSubtitle');
    const count = document.getElementById('playerCount');
    const dots = document.getElementById('playerDots');
    const playBtn = document.getElementById('playerPlay');
    const SLIDE_MS = 5000;
    let index = 0;
    let timer = null;

    const slides = figures.map((figure, i) => {
        const source = figure.querySelector('img');
        const img = document.createElement('img');
        img.src = source.getAttribute('src');
        img.alt = source.alt;
        img.loading = i === 0 ? 'eager' : 'lazy';
        screen.appendChild(img);

        const dot = document.createElement('button');
        dot.type = 'button';
        dot.className = 'dot';
        dot.setAttribute('aria-label', `Step ${i + 1}`);
        dot.addEventListener('click', () => { stop(); show(i); });
        dots.appendChild(dot);
        return { img, dot, text: figure.dataset.subtitle };
    });

    function show(next) {
        index = (next + slides.length) % slides.length;
        slides.forEach((slide, i) => {
            slide.img.classList.toggle('is-current', i === index);
            slide.dot.setAttribute('aria-current', String(i === index));
        });
        subtitle.innerHTML = slides[index].text;
        count.textContent = `${index + 1} / ${slides.length}`;
    }
    function play() {
        timer = setInterval(() => show(index + 1), SLIDE_MS);
        playBtn.textContent = 'Pause';
    }
    function stop() {
        clearInterval(timer);
        timer = null;
        playBtn.textContent = 'Play';
    }

    playBtn.addEventListener('click', () => (timer ? stop() : play()));
    document.getElementById('playerPrev').addEventListener('click', () => { stop(); show(index - 1); });
    document.getElementById('playerNext').addEventListener('click', () => { stop(); show(index + 1); });
    screen.addEventListener('click', () => { stop(); show(index + 1); });
    show(0);
})();
