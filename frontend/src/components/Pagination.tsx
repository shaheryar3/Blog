/**
 * Pagination Component
 * 
 * This component provides navigation between pages of content.
 * It includes smart page numbering and responsive design.
 * 
 * Learning Notes:
 * - Math functions help calculate page ranges and boundaries
 * - Conditional rendering shows/hides elements based on state
 * - Bootstrap pagination provides consistent styling
 * - Component props allow customization while maintaining reusability
 */

import React from 'react';
import { Pagination as BootstrapPagination } from 'react-bootstrap';

// Component props interface
interface PaginationProps {
  currentPage: number;
  totalPages: number;
  onPageChange: (page: number) => void;
  maxVisiblePages?: number;
}

const Pagination: React.FC<PaginationProps> = ({ 
  currentPage, 
  totalPages, 
  onPageChange,
  maxVisiblePages = 5 
}) => {
  // Don't render if there's only one page or no pages
  if (totalPages <= 1) {
    return null;
  }

  /**
   * Calculate which page numbers to display
   * 
   * This function determines the range of page numbers to show
   * based on the current page and maximum visible pages.
   */
  const getVisiblePages = (): number[] => {
    const pages: number[] = [];
    
    // Calculate start and end of visible range
    let start = Math.max(1, currentPage - Math.floor(maxVisiblePages / 2));
    let end = Math.min(totalPages, start + maxVisiblePages - 1);
    
    // Adjust start if end hits the boundary
    if (end - start + 1 < maxVisiblePages) {
      start = Math.max(1, end - maxVisiblePages + 1);
    }
    
    // Generate page numbers array
    for (let i = start; i <= end; i++) {
      pages.push(i);
    }
    
    return pages;
  };

  const visiblePages = getVisiblePages();
  const showFirstPage = visiblePages[0] > 1;
  const showLastPage = visiblePages[visiblePages.length - 1] < totalPages;
  const showFirstEllipsis = visiblePages[0] > 2;
  const showLastEllipsis = visiblePages[visiblePages.length - 1] < totalPages - 1;

  return (
    <div className="d-flex justify-content-center">
      <BootstrapPagination>
        {/* Previous Button */}
        <BootstrapPagination.Prev
          disabled={currentPage === 1}
          onClick={() => onPageChange(currentPage - 1)}
        />
        
        {/* First Page */}
        {showFirstPage && (
          <>
            <BootstrapPagination.Item
              active={currentPage === 1}
              onClick={() => onPageChange(1)}
            >
              1
            </BootstrapPagination.Item>
            
            {/* First Ellipsis */}
            {showFirstEllipsis && (
              <BootstrapPagination.Ellipsis disabled />
            )}
          </>
        )}
        
        {/* Visible Page Numbers */}
        {visiblePages.map(page => (
          <BootstrapPagination.Item
            key={page}
            active={page === currentPage}
            onClick={() => onPageChange(page)}
          >
            {page}
          </BootstrapPagination.Item>
        ))}
        
        {/* Last Page */}
        {showLastPage && (
          <>
            {/* Last Ellipsis */}
            {showLastEllipsis && (
              <BootstrapPagination.Ellipsis disabled />
            )}
            
            <BootstrapPagination.Item
              active={currentPage === totalPages}
              onClick={() => onPageChange(totalPages)}
            >
              {totalPages}
            </BootstrapPagination.Item>
          </>
        )}
        
        {/* Next Button */}
        <BootstrapPagination.Next
          disabled={currentPage === totalPages}
          onClick={() => onPageChange(currentPage + 1)}
        />
      </BootstrapPagination>
    </div>
  );
};

export default Pagination;