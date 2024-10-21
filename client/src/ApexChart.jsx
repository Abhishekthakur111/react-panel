import React, { Component } from 'react';
import ReactApexChart from 'react-apexcharts';
import axios from 'axios';
import { BASE_URL } from './Config';

class ApexChart extends Component {
  constructor(props) {
    super(props);

    this.state = {
      series: [{
        name: 'Users',
        data: [],
      }],
      options: {
        chart: {
          height: 350,
          type: 'bar',
        },
        colors: ['#D81B60'], 
        plotOptions: {
          bar: {
            borderRadius: 10,
            dataLabels: {
              position: 'top',
            },
          },
        },
        dataLabels: {
          enabled: true,
          formatter: function (val) {
            return val === 0 ? '' : val;
          },
          offsetY: -20,
          style: {
            fontSize: '12px',
            colors: ["#D81B60"],
          },
        },
        xaxis: {
          categories: [], 
          position: 'bottom',
          axisBorder: {
            show: true,
          },
          axisTicks: {
            show: false,
          },
          crosshairs: {
            fill: {
              type: 'gradient',
              gradient: {
                colorFrom: '#D8E3F0',
                colorTo: '#BED1E6',
                stops: [0, 100],
                opacityFrom: 0.4,
                opacityTo: 0.5,
              },
            },
          },
          tooltip: {
            enabled: true,
          },
        },
        yaxis: {
          axisBorder: {
            show: false,
          },
          axisTicks: {
            show: false,
          },
          labels: {
            show: true,
            formatter: function (val) {
              return val === 0 ? '' : val;
            },
          },
        },
      },
    };
  }

  componentDidMount() {
    this.fetchData();
  }

  fetchData = async () => {
    try {
      const response = await axios.post(`${BASE_URL}/graph`);
      const { data, categories } = response.data;

      this.setState({
        series: [{ name: 'Users', data }],
        options: {
          ...this.state.options,
          xaxis: {
            ...this.state.options.xaxis,
            categories: categories,  
          },
        },
      });
    } catch (error) {
      console.error("Error fetching data:", error);
    }
  };                              

  render() {
    return (
      
        
        <div className="col-12">
          <div className="card card-statistics">
            <div className="card-header">
              <h4 className="card-title">Users Chart</h4>
            </div>
            <div className="card-body">
              <ReactApexChart 
                options={this.state.options} 
                series={this.state.series} 
                type="bar" 
                height={300} 
              />
            </div>
          </div>
        </div>
    
    );
  }
}

export default ApexChart;
