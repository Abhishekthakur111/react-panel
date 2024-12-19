import React, { useState } from "react";
import { Calendar as BigCalendar, Views, dateFnsLocalizer } from "react-big-calendar";
import { format, parse, startOfWeek, getDay, isSameDay, startOfToday } from "date-fns";
import "react-big-calendar/lib/css/react-big-calendar.css";
import { ToastContainer } from "react-toastify";
import "@fortawesome/fontawesome-free/css/all.min.css";

const locales = {
  "en-US": require("date-fns/locale/en-US"),
};

const localizer = dateFnsLocalizer({
  format,
  parse,
  startOfWeek,
  getDay,
  locales,
});

const CalendarPage = () => {
  const [events, setEvents] = useState([]); 
  const [view, setView] = useState(Views.MONTH); 

  const handleSelectSlot = ({ start, end }) => {
    const title = window.prompt("Enter event title:");
    if (title) {
      setEvents([...events, { start, end, title }]);
    }
  };

  const handleViewChange = (newView) => {
    setView(newView);
  };

  const today = startOfToday();

  const dayPropGetter = (date) => {
    if (isSameDay(date, today)) {
      return { style: { backgroundColor: "pink" } };
    }
    return {};
  };

  return (
    <>
      <ToastContainer
        position="top-right"
        autoClose={1000}
        hideProgressBar={false}
        newestOnTop={false}
        closeOnClick
        rtl={false}
        pauseOnFocusLoss
        draggable
        pauseOnHover
      />
      <div className="container-fluid">
        <div className="row">
          <div className="col-12">
            <div className="card my-4">
              <div className="card-header p-0 position-relative mt-n4 mx-3 z-index-2">
                <div className="bg-gradient-primary shadow-primary border-radius-lg pt-4 pb-3">
                  <h6 className="text-white text-capitalize ps-3">Calendar</h6>
                </div>
              </div>
              <div className="card shadow p-4">
                <BigCalendar
                  localizer={localizer}
                  events={events}
                  startAccessor="start"
                  endAccessor="end"
                  selectable
                  onSelectSlot={handleSelectSlot}
                  style={{ height: "70vh", width: "100%" }}
                  onView={handleViewChange}
                  view={view}
                  views={[Views.MONTH, Views.WEEK, Views.DAY, Views.AGENDA]}
                  dayPropGetter={dayPropGetter}
                />
              </div>
            </div>
          </div>
        </div>
      </div>
    </>
  );
};

export default CalendarPage;
