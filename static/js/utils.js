const Utils = {
    numbers: ({count, min, max}) => {
        return Array.from({ length: count }, () => Math.floor(Math.random() * (max - min + 1)) + min);
    },
    CHART_COLORS: {
        red: 'rgb(255, 99, 132)',
        blue: 'rgb(54, 162, 235)',
    },
};
