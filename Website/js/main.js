// Element references
const username = document.getElementById('sapid');
const password = document.getElementById('password');
const errorMessage = document.getElementById('error-message');
const togglePassword = document.getElementById('password-toggle');
const submitButton = document.getElementById('submit');
const attendanceForm = document.getElementById('attendance-form');
const attendanceReportContainer = document.getElementById('attendance-report-container');
const attendanceTable = document.getElementById('attendance-table');
const lineChartContainer = document.getElementById('line-chart-container');
const chartContainer = document.getElementById('charts-container');
const colorPalette = [
    'rgba(255, 99, 132, 0.7)', 'rgba(54, 162, 235, 0.7)', 'rgba(255, 206, 86, 0.7)', 'rgba(75, 192, 192, 0.7)',
    'rgba(153, 102, 255, 0.7)', 'rgba(255, 159, 64, 0.7)', 'rgba(201, 203, 207, 0.7)', 'rgba(255, 99, 71, 0.7)',
    'rgba(0, 255, 127, 0.7)', 'rgba(255, 20, 147, 0.7)', 'rgba(0, 191, 255, 0.7)', 'rgba(75, 0, 130, 0.7)',
    'rgba(173, 216, 230, 0.7)', 'rgba(240, 128, 128, 0.7)', 'rgba(124, 252, 0, 0.7)', 'rgba(255, 215, 0, 0.7)',
    'rgba(255, 105, 180, 0.7)', 'rgba(135, 206, 235, 0.7)', 'rgba(255, 140, 0, 0.7)'
];
let SAPIDTimeoutId, passwordTimeoutId, lineChartInstance;

const displayError = (element, condition) => {
    element.style.display = condition ? 'block' : 'none';
};

// Validation and event listeners
togglePassword.addEventListener('click', () => {
    password.type = password.type === 'password' ? 'text' : 'password';
    togglePassword.classList.toggle('show', password.type === 'text');
});

attendanceForm.addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        event.preventDefault();
        submitButton.click();
    }
});

submitButton.addEventListener('click', async (event) => {
    event.preventDefault();
    const isSAPIDValid = !isNaN(username.value);
    const isPasswordValid = password.value.length >= 8;

    if (!isSAPIDValid) {
        displayError(errorMessage, true);
        errorMessage.textContent = 'Please enter a valid SAP ID.';
        return;
    }
    if (!isPasswordValid) {
        displayError(errorMessage, true);
        errorMessage.textContent = 'Password must be at least 8 characters long.';
        return;
    }

    errorMessage.textContent = '';
    errorMessage.style.display = 'none';
    submitButton.disabled = true;
    submitButton.innerHTML = 'Loading <i class="fas fa-spinner fa-spin"></i>';

    try {
        const token = await new Promise((resolve, reject) => {
            turnstile.ready(() => {
              turnstile.render('.cf-turnstile', {
                callback: resolve,
                'error-callback': () => reject('Turnstile error. Please try again.'),
              });
            });
          });
        const response = await fetch('https://attendance-backend.spirax.me/v1/getAttendanceReport', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username.value,
                password: password.value,
                'cf-turnstile-response': token,
            })
        });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || 'Failed to fetch attendance.');

        renderAttendanceTable(data.data);
        renderLineChart(data.data.Attendance.LineGraph);
        renderBarChart(data.data.Attendance.Data);
        attendanceReportContainer.style.display = 'block';
        lineChartContainer.style.display = 'block';
        chartContainer.style.display = 'block';
    } catch (error) {
        errorMessage.textContent = error.message;
        errorMessage.style.display = 'block';
    } finally {
        submitButton.disabled = false;
        submitButton.innerHTML = 'Get Attendance';
    }

});

// Render functions
function renderAttendanceTable(data) {
    attendanceTable.innerHTML = '';
    const headerRow = attendanceTable.createTHead().insertRow();
    ['Subject', 'Present', 'Total', 'Percentage'].forEach(text => headerRow.insertCell().textContent = text);

    data.Attendance.Data.forEach(({
        Subject,
        Present,
        Total,
        Percentage
    }) => {
        const row = attendanceTable.insertRow();
        row.insertCell().textContent = Subject;
        row.insertCell().textContent = Present;
        row.insertCell().textContent = Total;
        row.insertCell().textContent = `${Percentage}%`;
        row.style.color = Percentage < 80 ? 'red' : Percentage === 100 ? '#32CD32' : 'white';
    });
}

function renderLineChart(attendanceData) {
    const allDatesArray = [...new Set(Object.keys(attendanceData).flatMap(subject => Object.keys(attendanceData[subject]).map(Number)))].sort((a, b) => a - b);
    const labels = allDatesArray.map(date => new Date(date));
    const datasets = Object.keys(attendanceData).map((subject, index) => ({
        label: subject,
        data: allDatesArray.map(date => attendanceData[subject][date] ?? null),
        backgroundColor: colorPalette[index % colorPalette.length],
        borderColor: colorPalette[index % colorPalette.length].replace(/0.7/, '1'),
        fill: false,
        tension: 0.4
    }));

    if (lineChartInstance) lineChartInstance.destroy();
    lineChartInstance = new Chart(document.getElementById('line-chart').getContext('2d'), {
        type: 'line',
        data: {
            labels,
            datasets
        },
        options: {
            responsive: true,
            spanGaps: true,
            scales: {
                x: {
                    type: 'time',
                    time: {
                        unit: 'month',
                        displayFormats: {
                            month: 'MMM yyyy'
                        }
                    }
                },
                y: {
                    min: 0,
                    max: 100,
                    ticks: {
                        stepSize: 10,
                        callback: val => `${val}%`
                    }
                }
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        title: ctx => ctx[0].label.slice(0, 12).replace(/,\s*$/, ""),
                        label: ctx => `${ctx.dataset.label || ''}: ${ctx.raw || 0}%`
                    }
                }
            }
        }
    });
    lineChartInstance.data.datasets.forEach((_, idx) => {
        if (idx !== 0) lineChartInstance.data.datasets[idx].hidden = true;
    });
}

function renderBarChart(data) {
    const labels = data.map(({
        Subject
    }) => Subject.replace(/[^A-Z]/g, ''));
    const ctx = document.getElementById('bar-chart').getContext('2d');
    const chart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels,
            datasets: [{
                data: data.map(({
                    Percentage
                }) => Percentage),
                backgroundColor: colorPalette.slice(0, data.length),
                borderColor: colorPalette.slice(0, data.length).map(c => c.replace(/, 0.7\)/, ', 1)'))
            }]
        },
        options: {
            responsive: true,
            scales: {
                x: {
                    stacked: true
                },
                y: {
                    ticks: {
                        stepSize: 10,
                        callback: val => `${val}%`
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    callbacks: {
                        label: ctx => `${ctx.label || ''}: ${ctx.raw || 0}%`
                    }
                },
                annotation: {
                    annotations: [{
                        id: 'min-attendance',
                        type: 'line',
                        mode: 'horizontal',
                        scaleID: 'y',
                        value: 80,
                        borderColor: 'red',
                        borderWidth: 2
                    }]
                }
            }
        }
    });
    setTimeout(() => chart.update(), 500);
}

// Spinner and back-to-top button
const spinner = () => setTimeout(() => document.getElementById('spinner')?.classList.remove('show'), 1);
spinner();

const debounce = (func, delay) => {
    let timeout;
    return function(...args) {
        clearTimeout(timeout);
        timeout = setTimeout(() => func.apply(this, args), delay);
    };
};

const handleScroll = debounce(() => {
    document.querySelector('.back-to-top').style.display = window.scrollY > 300 ? 'block' : 'none';
}, 300);

window.addEventListener('scroll', handleScroll);

document.querySelector('.back-to-top').addEventListener('click', (e) => {
    e.preventDefault();
    window.scrollTo({
        top: 0,
        behavior: 'smooth'
    });
});