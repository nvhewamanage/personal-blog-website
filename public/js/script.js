/* =============================================
   script.js — Single Page Portfolio
   ============================================= */

// ── DOM refs ──────────────────────────────────
const navbar    = document.getElementById('navbar');
const hamburger = document.getElementById('hamburger');
const navLinks  = document.getElementById('navLinks');
const navItems  = document.querySelectorAll('.nav-link');
const sections  = document.querySelectorAll('section[id]');

// ── Navbar: scroll shadow ─────────────────────
window.addEventListener('scroll', () => {
  navbar.classList.toggle('scrolled', window.scrollY > 24);
  highlightActiveNav();
}, { passive: true });

// ── Hamburger menu ────────────────────────────
hamburger.addEventListener('click', () => {
  const open = navLinks.classList.toggle('open');
  const spans = hamburger.querySelectorAll('span');
  if (open) {
    spans[0].style.transform = 'rotate(45deg) translate(5px, 5px)';
    spans[1].style.opacity   = '0';
    spans[2].style.transform = 'rotate(-45deg) translate(5px, -5px)';
    hamburger.setAttribute('aria-expanded', 'true');
  } else {
    spans.forEach(s => { s.style.transform = ''; s.style.opacity = ''; });
    hamburger.setAttribute('aria-expanded', 'false');
  }
});

// Close hamburger when a nav link is clicked
navLinks.querySelectorAll('.nav-link').forEach(link => {
  link.addEventListener('click', () => {
    navLinks.classList.remove('open');
    hamburger.querySelectorAll('span').forEach(s => {
      s.style.transform = '';
      s.style.opacity   = '';
    });
    hamburger.setAttribute('aria-expanded', 'false');
  });
});

// ── Smooth scroll for all internal links ─────
document.querySelectorAll('a[href^="#"], .scroll-link').forEach(link => {
  link.addEventListener('click', e => {
    const href = link.getAttribute('href');
    if (!href || !href.startsWith('#')) return;
    const target = document.querySelector(href);
    if (!target) return;
    e.preventDefault();
    const offset = navbar.offsetHeight + 8;
    const top    = target.getBoundingClientRect().top + window.scrollY - offset;
    window.scrollTo({ top, behavior: 'smooth' });
  });
});

// ── Active nav highlight on scroll ───────────
function highlightActiveNav() {
  let current = 'home';
  const offset = navbar.offsetHeight + 60;

  sections.forEach(sec => {
    if (window.scrollY >= sec.offsetTop - offset) {
      current = sec.id;
    }
  });

  navItems.forEach(item => {
    item.classList.toggle('active', item.dataset.section === current);
  });
}

highlightActiveNav(); // Run on load

// ── Reveal on scroll ─────────────────────────
const revealEls = document.querySelectorAll(
  '.reveal, .blog-card, .gallery-item, .fact-item'
);

const revealObserver = new IntersectionObserver((entries) => {
  entries.forEach((entry, i) => {
    if (entry.isIntersecting) {
      const el = entry.target;
      // Stagger siblings inside same parent
      const siblings = [...el.parentElement.children].filter(
        c => c.classList.contains(el.classList[0])
      );
      const idx = siblings.indexOf(el);
      setTimeout(() => {
        el.classList.add('visible');
        el.style.transitionDelay = '';
      }, idx * 70);
      revealObserver.unobserve(el);
    }
  });
}, { threshold: 0.08, rootMargin: '0px 0px -40px 0px' });

revealEls.forEach(el => {
  el.classList.add('reveal');
  revealObserver.observe(el);
});

// ── Gallery filter ───────────────────────────
const filterBtns   = document.querySelectorAll('.filter-btn');
const galleryItems = document.querySelectorAll('.gallery-item');

filterBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    filterBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');

    const filter = btn.dataset.filter;
    galleryItems.forEach(item => {
      const match = filter === 'all' || item.dataset.category === filter;
      item.classList.toggle('hidden', !match);
    });
  });
});

// ── Contact form (client-side, no backend) ───
const contactForm   = document.getElementById('contactForm');
const formSuccess   = document.getElementById('formSuccess');
const formSuccessMsg = document.getElementById('formSuccessMsg');

if (contactForm) {
  contactForm.addEventListener('submit', e => {
    e.preventDefault();

    const fields = contactForm.querySelectorAll('[required]');
    let valid = true;

    fields.forEach(field => {
      field.classList.remove('error');
      if (!field.value.trim()) {
        field.classList.add('error');
        valid = false;
        field.addEventListener('input', () => field.classList.remove('error'), { once: true });
      }
      if (field.type === 'email' && field.value && !field.value.includes('@')) {
        field.classList.add('error');
        valid = false;
      }
    });

    if (!valid) return;

    const name = document.getElementById('name').value.trim();

    // Simulate send (replace with fetch/API call for real backend)
    const btn = contactForm.querySelector('.btn-submit');
    btn.textContent = 'Sending…';
    btn.disabled = true;

    setTimeout(() => {
      formSuccessMsg.textContent =
        `Thanks ${name}! Your message has been received. I'll get back to you soon. ✨`;
      formSuccess.style.display = 'flex';
      contactForm.reset();
      btn.innerHTML = 'Send Message <i class="fa-solid fa-paper-plane"></i>';
      btn.disabled = false;
      formSuccess.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
    }, 900);
  });
}

// ── Newsletter subscribe ──────────────────────
const newsletterBtn     = document.getElementById('newsletterBtn');
const newsletterEmail   = document.getElementById('newsletterEmail');
const newsletterSuccess = document.getElementById('newsletterSuccess');
const newsletterForm    = document.getElementById('newsletterForm');

if (newsletterBtn) {
  newsletterBtn.addEventListener('click', () => {
    const email = newsletterEmail.value.trim();

    if (!email || !email.includes('@')) {
      newsletterEmail.style.outline = '2px solid #e8154a';
      setTimeout(() => newsletterEmail.style.outline = '', 1500);
      return;
    }

    newsletterBtn.textContent = 'Subscribing…';
    newsletterBtn.disabled = true;

    setTimeout(() => {
      newsletterForm.style.display = 'none';
      newsletterSuccess.textContent =
        `🎉 You're in! Welcome aboard, ${email}`;
      newsletterSuccess.style.display = 'block';
    }, 700);
  });

  // Also trigger on Enter key in input
  newsletterEmail.addEventListener('keydown', e => {
    if (e.key === 'Enter') newsletterBtn.click();
  });
}