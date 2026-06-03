export interface ContinueReading {
  classId: string;
  subjectId: string;
  bookId: string;
  bookTitle: string;
  chapterId: string;
  chapterTitle: string;
  chapterUrl: string;
  chapterType: 'pdf' | 'html';
  lastOpenedAt: string;
}

const CONTINUE_KEY = 'ncert:continue-reading';
const BOOKMARKS_KEY = 'ncert:bookmarks';

class ReadingStateService {
  getContinueReading(): ContinueReading | null {
    try {
      const item = localStorage.getItem(CONTINUE_KEY);
      if (!item) return null;
      return JSON.parse(item) as ContinueReading;
    } catch {
      return null;
    }
  }

  saveContinueReading(value: ContinueReading): void {
    localStorage.setItem(CONTINUE_KEY, JSON.stringify(value));
  }

  private getBookmarks(): string[] {
    try {
      const item = localStorage.getItem(BOOKMARKS_KEY);
      if (!item) return [];
      return JSON.parse(item) as string[];
    } catch {
      return [];
    }
  }

  private saveBookmarks(items: string[]): void {
    localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(items));
  }

  isBookmarked(bookId: string, chapterId: string): boolean {
    return this.getBookmarks().includes(`${bookId}:${chapterId}`);
  }

  toggleBookmark(bookId: string, chapterId: string): void {
    const key = `${bookId}:${chapterId}`;
    const current = this.getBookmarks();
    if (current.includes(key)) {
      this.saveBookmarks(current.filter((item) => item !== key));
      return;
    }
    this.saveBookmarks([key, ...current].slice(0, 100));
  }
}

export const readingStateService = new ReadingStateService();
