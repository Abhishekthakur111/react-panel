// Pagination.js
import React from "react";

const Pagination = ({ currentPage, totalPages, onPageChange }) => {
  const handlePageChange = (page) => {
    if (page >= 1 && page <= totalPages) {
      onPageChange(page);
    }
  };

  return (
    <div className="card-footer text-right">
      <nav className="d-inline-block">
        <ul className="pagination mb-0">
          <li className={`page-item ${currentPage === 1 ? "disabled" : ""}`}>
            <a
              className="page-link"
              href="#"
              onClick={() => handlePageChange(currentPage - 1)}
            >
              <i className="fas fa-chevron-left" />
            </a>
          </li>
          {[...Array(totalPages).keys()].map((page) => (
            <li
              key={page}
              className={`page-item ${currentPage === page + 1 ? "active" : ""}`}
            >
              <a
                className="page-link"
                href="#"
                onClick={() => handlePageChange(page + 1)}
              >
                {page + 1}
              </a>
            </li>
          ))}
          <li
            className={`page-item ${currentPage === totalPages ? "disabled" : ""}`}
          >
            <a
              className="page-link"
              href="#"
              onClick={() => handlePageChange(currentPage + 1)}
            >
              <i className="fas fa-chevron-right" />
            </a>
          </li>
        </ul>
      </nav>
    </div>
  );
};

export default Pagination;
